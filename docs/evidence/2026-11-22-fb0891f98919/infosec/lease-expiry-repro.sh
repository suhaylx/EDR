#!/usr/bin/env bash
set +x
set -euo pipefail
review_dir=/workspace/scratch/39b05ab721e3/infosec-review
source_dir=${EDR_REVIEW_SOURCE_DIR:-/workspace/scratch/39b05ab721e3/EDR}
export PATH=/workspace/scratch/39b05ab721e3/toolchains/pgsql/bin:$PATH
review_pg=$(mktemp -d "$review_dir/lease-pg-XXXXXX")
cleanup() {
  pg_ctl -D "$review_pg/data" -m immediate stop >/dev/null 2>&1 || true
  rm -rf "$review_pg"
}
trap cleanup EXIT
initdb -D "$review_pg/data" -A trust > "$review_dir/lease-pg-init.log"
pg_ctl -D "$review_pg/data" -l "$review_dir/lease-pg.log" -o "-k '' -h 127.0.0.1 -p 55497" start >/dev/null
export PGHOST=127.0.0.1 PGPORT=55497 PGUSER=agent PGDATABASE=postgres
createdb edr_infosec_lease
export PGDATABASE=edr_infosec_lease
for migration in "$source_dir"/backend/migrations/*.up.sql; do
  if [[ -n "${EDR_REVIEW_MIGRATION_OVERRIDE:-}" && -f "$EDR_REVIEW_MIGRATION_OVERRIDE/$(basename "$migration")" ]]; then
    migration="$EDR_REVIEW_MIGRATION_OVERRIDE/$(basename "$migration")"
  fi
  psql -X -q -v ON_ERROR_STOP=1 -f "$migration" >/dev/null
done
psql -X -q -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE lease_runtime LOGIN INHERIT;
CREATE ROLE lease_registry LOGIN INHERIT;
SQL
psql -X -q -v ON_ERROR_STOP=1 -v runtime_login=lease_runtime -v registry_login=lease_registry -v dedicated_edr_database=true -f "$source_dir/backend/bootstrap/runtime_privileges.sql" >/dev/null
psql -X -q -v ON_ERROR_STOP=1 <<'SQL'
INSERT INTO edr_tenants(tenant_id,display_name) VALUES('lease_race','Lease timing fixture');
INSERT INTO edr_agents(tenant_id,agent_id,platform) VALUES('lease_race','linux01','linux');
INSERT INTO edr_agent_certificates(tenant_id,agent_id,fingerprint_sha256,not_before,not_after)
 VALUES('lease_race','linux01',decode(repeat('aa',32),'hex'),clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 day');
INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root,state,lease_owner,lease_token,lease_expires_at,attempt_count)
VALUES('11111111-1111-4111-8111-111111111111','lease_race','linux01','/tmp/synthetic','leased','linux01',
 '22222222-2222-4222-8222-222222222222',clock_timestamp()+interval '1 second',1);
SQL
export EDR_LEASE_REPRO_READY="$review_pg/ready" EDR_LEASE_REPRO_FIFO="$review_pg/release"
mkfifo "$EDR_LEASE_REPRO_FIFO"
cat > "$review_pg/lock.sql" <<'SQL'
BEGIN;
SELECT 1 FROM edr_agent_certificates WHERE tenant_id='lease_race' FOR UPDATE;
\! touch "$EDR_LEASE_REPRO_READY"
\! timeout 10 sh -c 'IFS= read -r release < "$EDR_LEASE_REPRO_FIFO"'
COMMIT;
SQL
psql -X -q -v ON_ERROR_STOP=1 -f "$review_pg/lock.sql" > "$review_pg/admin.log" &
admin_pid=$!
for ((probe=0;probe<100;probe++)); do
  [[ -f "$EDR_LEASE_REPRO_READY" ]] && break
  sleep 0.02
done
[[ -f "$EDR_LEASE_REPRO_READY" ]]
cat > "$review_pg/runtime.sql" <<'SQL'
BEGIN;
SET application_name='infosec_lease_wait';
SELECT public.edr_authorize_agent_certificate('lease_race','linux01',decode(repeat('aa',32),'hex')) AS authorized;
SELECT clock_timestamp()-transaction_timestamp() AS elapsed_after_authorization;
SELECT public.edr_complete_scan_job_with_result('lease_race','linux01',
 '11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222',
 'error','','synthetic timing fixture') AS expired_completion_accepted;
COMMIT;
SQL
PGUSER=lease_runtime psql -X -q -v ON_ERROR_STOP=1 -f "$review_pg/runtime.sql" > "$review_pg/runtime.log" &
runtime_pid=$!
observed=false
for ((probe=0;probe<100;probe++)); do
  waiting=$(psql -X -qAt -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_stat_activity WHERE application_name='infosec_lease_wait' AND wait_event_type='Lock'")
  if [[ "$waiting" == 1 ]]; then observed=true; break; fi
  sleep 0.02
done
[[ "$observed" == true ]]
echo 'Observed actual runtime certificate authorization lock wait.'
psql -X -q -v ON_ERROR_STOP=1 <<'SQL'
SELECT pg_sleep(GREATEST(0,extract(epoch FROM lease_expires_at-clock_timestamp())+0.03)) FROM edr_scan_jobs WHERE tenant_id='lease_race';
SELECT lease_expires_at < clock_timestamp() AS expired_before_authorization_released FROM edr_scan_jobs WHERE tenant_id='lease_race';
SQL
printf 'release\n' > "$EDR_LEASE_REPRO_FIFO"
wait "$admin_pid"
wait "$runtime_pid"
cat "$review_pg/runtime.log"
psql -X -q -v ON_ERROR_STOP=1 -c "SELECT count(*) AS persisted_after_expired_lease FROM edr_scan_job_results WHERE tenant_id='lease_race'"
if [[ "${EDR_REVIEW_EXPECT_REJECTION:-false}" == true ]]; then
  rejected=$(psql -X -qAt -v ON_ERROR_STOP=1 -c "SELECT NOT EXISTS (SELECT 1 FROM edr_scan_job_results WHERE tenant_id='lease_race') AND EXISTS (SELECT 1 FROM edr_scan_jobs WHERE tenant_id='lease_race' AND state='leased')")
  [[ "$rejected" == t ]]
  echo 'PASS: expired lease result denied with no persisted result or lease mutation.'
fi
