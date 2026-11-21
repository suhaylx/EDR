#!/usr/bin/env bash
# P0 QA: a revocation transaction must serialize with an in-flight claim.
# Run only against disposable CI PostgreSQL AFTER queue schema tests.
set -euo pipefail
: "${EDR_TEST_DATABASE_URL:?Set disposable PostgreSQL URL}"
[[ "${EDR_QA_DISPOSABLE_DB:-}" == "yes" ]] || { echo 'Disposable DB flag required' >&2; exit 2; }
command -v psql >/dev/null
command -v timeout >/dev/null

tmp="$(mktemp -d)"
export QA_LOCK_READY_FILE="$tmp/ready"
export QA_LOCK_RELEASE_FIFO="$tmp/release"
mkfifo "$QA_LOCK_RELEASE_FIFO"
holder=''
claimer1=''
claimer2=''
cleanup() {
  rc=$?
  trap - EXIT
  for pid in "$holder" "$claimer1" "$claimer2"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  if (( rc != 0 )); then
    for name in holder claim-agent claim-tenant; do
      echo "QA concurrency output: $name" >&2
      cat "$tmp/$name.log" >&2 2>/dev/null || true
    done
  fi
  # Delete only our unique disposable test tenants.
  psql "$EDR_TEST_DATABASE_URL" -X -q -v ON_ERROR_STOP=1 >/dev/null <<'SQL' || true
BEGIN;
DELETE FROM edr_scan_jobs WHERE tenant_id IN ('qa-lockagent','qa-locktenant');
DELETE FROM edr_agents WHERE tenant_id IN ('qa-lockagent','qa-locktenant');
DELETE FROM edr_tenants WHERE tenant_id IN ('qa-lockagent','qa-locktenant');
COMMIT;
SQL
  rm -rf "$tmp"
  exit "$rc"
}
trap cleanup EXIT

psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
BEGIN;
INSERT INTO edr_tenants(tenant_id,display_name)
VALUES ('qa-lockagent','Agent revocation race'),('qa-locktenant','Tenant disable race');
INSERT INTO edr_agents(tenant_id,agent_id,platform)
VALUES ('qa-lockagent','linux01','linux'),('qa-locktenant','win01','windows');
INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root)
VALUES ('b1111111-1111-4111-8111-111111111111','qa-lockagent','linux01','/qa'),
       ('b2222222-2222-4222-8222-222222222222','qa-locktenant','win01','C:/QA');
COMMIT;
SQL

# The administrator holds both principal row-update locks without committing.
# Claimers must wait for the transaction's outcome; stale reads cannot issue
# a lease after disable/revocation commits.
PGAPPNAME=qa_revoke_holder timeout 35 psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 >"$tmp/holder.log" 2>&1 <<'SQL' &
BEGIN;
UPDATE edr_agents SET revoked_at=clock_timestamp()
WHERE tenant_id='qa-lockagent' AND agent_id='linux01';
UPDATE edr_tenants SET disabled_at=clock_timestamp()
WHERE tenant_id='qa-locktenant';
\! touch "$QA_LOCK_READY_FILE"
\! timeout 28 sh -c 'IFS= read -r response < "$QA_LOCK_RELEASE_FIFO"'
COMMIT;
SQL
holder=$!

ready=0
for (( i=0; i<100; i++ )); do
  if [[ -f "$QA_LOCK_READY_FILE" ]]; then ready=1; break; fi
  if ! kill -0 "$holder" 2>/dev/null; then exit 1; fi
  sleep 0.1
done
[[ "$ready" == "1" ]] || { echo 'Revocation holder did not reach lock checkpoint' >&2; exit 1; }

PGAPPNAME=qa_claim_locked_agent timeout 30 psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 >"$tmp/claim-agent.log" 2>&1 <<'SQL' &
DO $agent_claim$
BEGIN
 IF EXISTS(SELECT 1 FROM edr_claim_scan_job('qa-lockagent','linux01','concurrent-agent',
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',60)) THEN
   RAISE EXCEPTION 'claimed job for agent revoked by committed transaction'; END IF;
END $agent_claim$;
SQL
claimer1=$!

PGAPPNAME=qa_claim_locked_tenant timeout 30 psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 >"$tmp/claim-tenant.log" 2>&1 <<'SQL' &
DO $tenant_claim$
BEGIN
 IF EXISTS(SELECT 1 FROM edr_claim_scan_job('qa-locktenant','win01','concurrent-tenant',
    'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',60)) THEN
   RAISE EXCEPTION 'claimed job for disabled tenant after admin commit'; END IF;
END $tenant_claim$;
SQL
claimer2=$!

# Confirm overlap at the database lock wait point, not just wall-clock timing.
blocked=0
for (( i=0; i<100; i++ )); do
  n="$(psql "$EDR_TEST_DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c \
    "SELECT count(DISTINCT application_name) FROM pg_stat_activity
     WHERE application_name IN ('qa_claim_locked_agent','qa_claim_locked_tenant')
       AND wait_event_type='Lock'")"
  if [[ "$n" == "2" ]]; then blocked=1; break; fi
  if ! kill -0 "$claimer1" 2>/dev/null || ! kill -0 "$claimer2" 2>/dev/null; then break; fi
  sleep 0.1
done
if [[ "$blocked" != "1" ]]; then
  echo 'Claims were not both serialized behind principal revocation locks' >&2
  exit 1
fi

printf 'release\n' | timeout 5 tee "$QA_LOCK_RELEASE_FIFO" >/dev/null
wait "$holder"
holder=''
wait "$claimer1"
claimer1=''
wait "$claimer2"
claimer2=''

psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
DO $verify$
BEGIN
 IF (SELECT count(*) FROM edr_scan_jobs WHERE
   tenant_id IN ('qa-lockagent','qa-locktenant')
   AND state='pending' AND attempt_count=0
   AND lease_token IS NULL AND lease_owner IS NULL)<>2 THEN
   RAISE EXCEPTION 'revocation racing with claim changed queue state'; END IF;
 IF EXISTS(SELECT 1 FROM edr_claim_scan_job('qa-lockagent','linux01','after-revoke',
   'cccccccc-cccc-4ccc-8ccc-cccccccccccc',30)) THEN
   RAISE EXCEPTION 'committed revoked agent later claimed job'; END IF;
 IF EXISTS(SELECT 1 FROM edr_claim_scan_job('qa-locktenant','win01','after-disable',
   'dddddddd-dddd-4ddd-8ddd-dddddddddddd',30)) THEN
   RAISE EXCEPTION 'committed disabled tenant later claimed job'; END IF;
END $verify$;
SQL

echo 'Concurrent agent revocation and tenant disablement serialized before queue claim'
