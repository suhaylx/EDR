#!/usr/bin/env bash
# QA P0: verify PostgreSQL committed scan queue state across an ACTUAL
# restart of the disposable GitHub Actions PostgreSQL service container.
# Usage: test-scan-job-db-restart.sh seed|verify (restart between phases).
set -euo pipefail
: "${EDR_TEST_DATABASE_URL:?Set disposable PostgreSQL connection URL}"
[[ "${EDR_QA_DISPOSABLE_DB:-}" == "yes" ]] || { echo "Disposable DB flag required" >&2; exit 2; }
command -v psql >/dev/null
case "${1:-}" in
  seed)
    psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
INSERT INTO edr_tenants(tenant_id,display_name) VALUES ('qa-db-restart','QA restart');
INSERT INTO edr_agents(tenant_id,agent_id,platform)
VALUES ('qa-db-restart','pending','linux'),
       ('qa-db-restart','leased','windows'),
       ('qa-db-restart','expired','linux');
INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root,max_attempts)
VALUES ('a1111111-1111-4111-8111-111111111111','qa-db-restart','pending','/qa/pending',3),
       ('a2222222-2222-4222-8222-222222222222','qa-db-restart','leased','C:/QA',3),
       ('a3333333-3333-4333-8333-333333333333','qa-db-restart','expired','/qa/expired',3);
DO $seed$
DECLARE a record; b record;
BEGIN
 SELECT * INTO a FROM edr_claim_scan_job('qa-db-restart','leased','before-restart',
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',300);
 SELECT * INTO b FROM edr_claim_scan_job('qa-db-restart','expired','before-restart',
   'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',300);
 IF a.job_id IS DISTINCT FROM 'a2222222-2222-4222-8222-222222222222'::uuid
 OR b.job_id IS DISTINCT FROM 'a3333333-3333-4333-8333-333333333333'::uuid
 THEN RAISE EXCEPTION 'pre-restart lease fixture failed'; END IF;
END $seed$;
UPDATE edr_scan_jobs
 SET lease_expires_at=transaction_timestamp()-interval '5 seconds'
 WHERE tenant_id='qa-db-restart' AND agent_id='expired';
COMMIT;
SQL
    echo 'Committed pending/leased/expired rows before database restart'
    ;;
  verify)
    psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
DO $verify$
DECLARE a record; b record;
BEGIN
 IF (SELECT count(*) FROM edr_scan_jobs WHERE tenant_id='qa-db-restart')<>3 THEN
   RAISE EXCEPTION 'committed rows lost across PostgreSQL restart'; END IF;
 IF NOT EXISTS(SELECT 1 FROM edr_scan_jobs
   WHERE tenant_id='qa-db-restart' AND agent_id='pending'
   AND state='pending' AND attempt_count=0) THEN
   RAISE EXCEPTION 'pending job not durable'; END IF;
 IF NOT EXISTS(SELECT 1 FROM edr_scan_jobs
   WHERE tenant_id='qa-db-restart' AND agent_id='leased'
   AND state='leased' AND attempt_count=1
   AND lease_token='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa') THEN
   RAISE EXCEPTION 'active lease not durable'; END IF;
 IF NOT EXISTS(SELECT 1 FROM edr_scan_jobs
   WHERE tenant_id='qa-db-restart' AND agent_id='expired'
   AND state='leased' AND attempt_count=1
   AND lease_token='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb') THEN
   RAISE EXCEPTION 'expired lease not durable'; END IF;
 IF NOT edr_complete_scan_job('qa-db-restart','leased',
   'a2222222-2222-4222-8222-222222222222',
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',true) THEN
   RAISE EXCEPTION 'pre-restart active lease cannot complete'; END IF;
 SELECT * INTO a FROM edr_claim_scan_job('qa-db-restart','pending','after-restart',
   'cccccccc-cccc-4ccc-8ccc-cccccccccccc',30);
 IF a.job_id IS DISTINCT FROM 'a1111111-1111-4111-8111-111111111111'::uuid
   OR a.attempt_count IS DISTINCT FROM 1 THEN
   RAISE EXCEPTION 'pre-restart pending job cannot claim'; END IF;
 IF edr_complete_scan_job('qa-db-restart','expired',
   'a3333333-3333-4333-8333-333333333333',
   'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',true) THEN
   RAISE EXCEPTION 'expired token accepted after restart'; END IF;
 IF edr_recover_expired_scan_jobs(10)<>1 THEN
   RAISE EXCEPTION 'expired job not recovered after restart'; END IF;
 SELECT * INTO b FROM edr_claim_scan_job('qa-db-restart','expired','after-restart',
   'dddddddd-dddd-4ddd-8ddd-dddddddddddd',30);
 IF b.job_id IS DISTINCT FROM 'a3333333-3333-4333-8333-333333333333'::uuid
   OR b.attempt_count IS DISTINCT FROM 2 THEN
   RAISE EXCEPTION 'expired job did not re-lease after restart'; END IF;
 IF edr_complete_scan_job('qa-db-restart','expired',b.job_id,
   'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',true) THEN
   RAISE EXCEPTION 'stale token replay accepted after restart'; END IF;
 IF NOT edr_complete_scan_job('qa-db-restart','expired',b.job_id,
   'dddddddd-dddd-4ddd-8ddd-dddddddddddd',true) THEN
   RAISE EXCEPTION 'new token rejected after restart'; END IF;
END $verify$;
SQL
    psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
DELETE FROM edr_scan_jobs WHERE tenant_id='qa-db-restart';
DELETE FROM edr_agents WHERE tenant_id='qa-db-restart';
DELETE FROM edr_tenants WHERE tenant_id='qa-db-restart';
COMMIT;
SQL
    echo 'Actual PostgreSQL service restart: pending/leased/recovery/replay persisted'
    ;;
  *) echo "Usage: $0 seed|verify" >&2; exit 2 ;;
esac
