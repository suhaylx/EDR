#!/usr/bin/env bash
# Mandatory SQL suites on fresh, local, disposable PostgreSQL databases.
# Restart is performed externally between seed/verify; verify proves the
# postmaster start time changed, then checks actual challenge and queue state.
set -Eeuo pipefail
cd "$(dirname "$0")/../.."

[[ "${EDR_QA_DISPOSABLE_DB:-}" == yes ]] || {
  echo 'EDR_QA_DISPOSABLE_DB=yes is required' >&2; exit 2;
}
[[ "${PGHOST:-}" == 127.0.0.1 && "${PGPORT:-}" == 5432 ]] || {
  echo 'Only the disposable IPv4 loopback PostgreSQL service on port 5432 is allowed' >&2; exit 2;
}
[[ "${PGUSER:-}" =~ ^[a-zA-Z_][a-zA-Z_0-9]*$ ]] || {
  echo 'A simple PostgreSQL role name is required' >&2; exit 2;
}
[[ "${EDR_CANDIDATE_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || {
  echo 'Full EDR_CANDIDATE_SHA is required' >&2; exit 2;
}
# libpq's inherited hostaddr/service settings can override an explicit URI's
# apparent loopback target. Refuse before even the version-check connection.
for qa_connection_override in PGHOSTADDR PGSERVICE PGSERVICEFILE; do
  [[ -z "${!qa_connection_override:-}" ]] || {
    echo 'Inherited PostgreSQL routing overrides are not permitted for QA' >&2; exit 2;
  }
done
command -v psql >/dev/null
command -v createdb >/dev/null
mkdir -p .quality-evidence
export PGCONNECT_TIMEOUT=5
export PGOPTIONS='-c statement_timeout=45000 -c lock_timeout=35000'
maintenance="postgresql://${PGUSER}@127.0.0.1:5432/postgres?sslmode=disable"
server_version="$(psql "$maintenance" -X -A -t -v ON_ERROR_STOP=1 -c 'SHOW server_version_num')"
[[ "$server_version" =~ ^16[0-9]{4}$ ]] || {
  echo 'This gate requires PostgreSQL 16' >&2; exit 2;
}

select_db() {
  [[ "$1" =~ ^edr_candidate_[a-z_]+$ || "$1" == edr_chain_test ]] || exit 2
  export EDR_TEST_DATABASE_URL="postgresql://${PGUSER}@127.0.0.1:5432/$1?sslmode=disable"
}
new_db() {
  select_db "$1"
  # No DROP or IF NOT EXISTS: an existing database must never be adopted.
  createdb --maintenance-db="$maintenance" "$1"
  psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -v sha="$EDR_CANDIDATE_SHA" <<'SQL'
CREATE TABLE edr_ci_candidate (source_sha text NOT NULL);
INSERT INTO edr_ci_candidate VALUES (:'sha');
SQL
}
apply_queue_schema() {
  for migration in 0001_agent_enrollment 0005_scan_job_queue 0007_scan_job_lease_renewal 0008_scan_job_results; do
    psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f "backend/migrations/${migration}.up.sql"
  done
}
apply_all_migrations() {
  for migration in backend/migrations/*.up.sql; do
    psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f "$migration"
  done
}

case "${1:-}" in
test)
  # Required files are intentionally not optional. A missing suite fails CI.
  python3 scripts/test-qa-db-targets.py
  bash scripts/test-soc-inventory-preflight.sh
  bash scripts/test-runtime-privileges-preflight.sh
  new_db edr_chain_test
  bash scripts/test-postgres-migration-chain.sh
  psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f scripts/test-scan-job-results.sql
  bash scripts/test-soc-endpoint-inventory-sql.sh

  new_db edr_candidate_enrollment_wallclock
  python3 scripts/test-enrollment-wallclock-races.py

  for suite in enrollment-migration atomic-agent-enrollment enrollment-challenges enrollment-revocation; do
    new_db "edr_candidate_${suite//-/_}"
    bash "scripts/test-${suite}.sh"
  done
  new_db edr_candidate_rotation
  bash scripts/test-certificate-rotation.sh
  bash scripts/test-certificate-rotation-tenant-race.sh

  new_db edr_candidate_queue
  bash scripts/test-scan-job-queue.sh
  bash scripts/test-scan-job-lease-renewal.sh

  for suite in concurrent-claims postcommit-revocation replay-exhaustion claim-revocation-race completion-revocation-race; do
    new_db "edr_candidate_${suite//-/_}"
    apply_queue_schema
    bash "scripts/test-scan-job-${suite}.sh"
  done
  new_db edr_candidate_grants
  bash scripts/test-runtime-privileges.sh
  ;;
seed)
  new_db edr_candidate_restart
  apply_all_migrations
  bash scripts/test-enrollment-challenge-db-restart.sh seed
  bash scripts/test-scan-job-db-restart.sh seed
  psql "$maintenance" -X -A -t -v ON_ERROR_STOP=1 -c 'SELECT pg_postmaster_start_time()::text' > .quality-evidence/postgres-start-before.txt
  ;;
verify)
  select_db edr_candidate_restart
  owner="$(psql "$EDR_TEST_DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c 'SELECT source_sha FROM edr_ci_candidate')"
  [[ "$owner" == "$EDR_CANDIDATE_SHA" ]] || {
    echo 'Restart database belongs to a different candidate' >&2; exit 2;
  }
  test -s .quality-evidence/postgres-start-before.txt
  before="$(cat .quality-evidence/postgres-start-before.txt)"
  after="$(psql "$maintenance" -X -A -t -v ON_ERROR_STOP=1 -c 'SELECT pg_postmaster_start_time()::text')"
  [[ -n "$before" && -n "$after" && "$before" != "$after" ]] || {
    echo 'Actual PostgreSQL restart was not observed' >&2; exit 1;
  }
  printf '%s\n' "$after" > .quality-evidence/postgres-start-after.txt
  bash scripts/test-enrollment-challenge-db-restart.sh verify
  bash scripts/test-scan-job-db-restart.sh verify
  ;;
*) echo "Usage: $0 test|seed|verify" >&2; exit 2 ;;
esac
echo "PASS: PostgreSQL candidate ${1} phase"
