#!/usr/bin/env bash
# P0 two-session lease contention; disposable PostgreSQL only.
set -euo pipefail
: "${EDR_TEST_DATABASE_URL:?Set a disposable PostgreSQL connection URL}"
[[ "${EDR_QA_DISPOSABLE_DB:-}" == "yes" ]] || { echo 'Disposable DB flag required' >&2; exit 2; }
command -v psql >/dev/null
tmp="$(mktemp -d)"
holder=''
cleanup() {
  if [[ -n "$holder" ]]; then kill "$holder" 2>/dev/null || true; wait "$holder" 2>/dev/null || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
INSERT INTO edr_tenants(tenant_id,display_name) VALUES ('qa-race','QA');
INSERT INTO edr_agents(tenant_id,agent_id,platform) VALUES ('qa-race','linux01','linux');
INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root)
VALUES ('77777777-7777-4777-8777-777777777777','qa-race','linux01','/qa');
SQL
PGAPPNAME=edr_qa_holder psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 >"$tmp/holder.log" 2>&1 <<'SQL' &
BEGIN;
DO $first$
DECLARE j record;
BEGIN
  SELECT * INTO j FROM edr_claim_scan_job('qa-race','linux01','first',
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',30);
  IF j.job_id IS DISTINCT FROM '77777777-7777-4777-8777-777777777777'::uuid
     THEN RAISE EXCEPTION 'first claim failed'; END IF;
END $first$;
SELECT pg_sleep(12);
COMMIT;
SQL
holder=$!
ready=0
for ((i=0;i<80;i++)); do
  if ! kill -0 "$holder" 2>/dev/null; then cat "$tmp/holder.log"; exit 1; fi
  n="$(psql "$EDR_TEST_DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_stat_activity WHERE application_name='edr_qa_holder' AND state='active' AND query LIKE 'SELECT pg_sleep(12)%'")"
  if [[ "$n" == "1" ]]; then ready=1; break; fi
  sleep 0.1
done
[[ "$ready" == 1 ]] || { cat "$tmp/holder.log"; exit 1; }
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
SET statement_timeout='3s';
DO $second$
BEGIN
 IF EXISTS(SELECT 1 FROM edr_claim_scan_job('qa-race','linux01','second',
   'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',30)) THEN
   RAISE EXCEPTION 'double claim while locked'; END IF;
END $second$;
SQL
wait "$holder"
holder=''
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
DO $verify$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM edr_scan_jobs WHERE tenant_id='qa-race'
   AND state='leased' AND lease_owner='first' AND attempt_count=1
   AND lease_token='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa') THEN
   RAISE EXCEPTION 'concurrent lease corrupted'; END IF;
 IF EXISTS(SELECT 1 FROM edr_claim_scan_job('qa-race','linux01','third',
   'cccccccc-cccc-4ccc-8ccc-cccccccccccc',30)) THEN
   RAISE EXCEPTION 'leased job claimed again'; END IF;
 IF edr_complete_scan_job('qa-race','linux01',
   '77777777-7777-4777-8777-777777777777',
   'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',true) THEN
   RAISE EXCEPTION 'loser token accepted'; END IF;
 IF NOT edr_complete_scan_job('qa-race','linux01',
   '77777777-7777-4777-8777-777777777777',
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',true) THEN
   RAISE EXCEPTION 'winner token rejected'; END IF;
END $verify$;
DELETE FROM edr_scan_jobs WHERE tenant_id='qa-race';
DELETE FROM edr_agents WHERE tenant_id='qa-race';
DELETE FROM edr_tenants WHERE tenant_id='qa-race';
SQL
echo 'Concurrent scan claim regression passed'
