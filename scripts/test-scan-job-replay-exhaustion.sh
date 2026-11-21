#!/usr/bin/env bash
# QA P0: committed-session replay rejection and retry exhaustion.
# Execute ONLY after queue schema test, against a disposable PostgreSQL database.
set -euo pipefail
: "${EDR_TEST_DATABASE_URL:?Set a disposable PostgreSQL connection URL}"
[[ "${EDR_QA_DISPOSABLE_DB:-}" == "yes" ]] || { echo "Disposable DB flag required" >&2; exit 2; }
command -v psql >/dev/null

# Session 1 commits two distinct scan leases.
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
INSERT INTO edr_tenants(tenant_id,display_name) VALUES ('qa-replay','QA replay');
INSERT INTO edr_agents(tenant_id,agent_id,platform)
VALUES ('qa-replay','replay','linux'),('qa-replay','exhaust','windows');
INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root,max_attempts)
VALUES ('88888888-8888-4888-8888-888888888888','qa-replay','replay','/qa/replay',2),
       ('99999999-9999-4999-8999-999999999999','qa-replay','exhaust','C:/QA',1);
DO $first$
DECLARE a record; b record;
BEGIN
 SELECT * INTO a FROM edr_claim_scan_job('qa-replay','replay','first',
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',30);
 SELECT * INTO b FROM edr_claim_scan_job('qa-replay','exhaust','first',
   'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',30);
 IF a.job_id IS DISTINCT FROM '88888888-8888-4888-8888-888888888888'::uuid
   OR a.attempt_count IS DISTINCT FROM 1 THEN
   RAISE EXCEPTION 'replay fixture lease failed'; END IF;
 IF b.job_id IS DISTINCT FROM '99999999-9999-4999-8999-999999999999'::uuid
   OR b.attempt_count IS DISTINCT FROM 1 THEN
   RAISE EXCEPTION 'exhaustion fixture lease failed'; END IF;
END $first$;
COMMIT;
SQL

# Session 2: emulate lease timeout; no backend/database restart is claimed.
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
UPDATE edr_scan_jobs SET lease_expires_at=transaction_timestamp()-interval '2 seconds'
WHERE tenant_id='qa-replay' AND state='leased';
COMMIT;
SQL

# Session 3: expired completion fails, recovery retries once or exhausts.
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
DO $recover$
DECLARE new_lease record;
BEGIN
 IF edr_complete_scan_job('qa-replay','replay',
   '88888888-8888-4888-8888-888888888888',
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',true) THEN
   RAISE EXCEPTION 'expired lease completion accepted'; END IF;
 IF edr_recover_expired_scan_jobs(10) <> 2 THEN
   RAISE EXCEPTION 'expected exactly two expired jobs to recover'; END IF;
 IF NOT EXISTS (SELECT 1 FROM edr_scan_jobs WHERE
   job_id='99999999-9999-4999-8999-999999999999'
   AND state='failed' AND attempt_count=1 AND lease_token IS NULL) THEN
   RAISE EXCEPTION 'exhausted job did not become terminal failed'; END IF;
 IF EXISTS(SELECT 1 FROM edr_claim_scan_job('qa-replay','exhaust','retry',
   'cccccccc-cccc-4ccc-8ccc-cccccccccccc',30)) THEN
   RAISE EXCEPTION 'exhausted job re-leased'; END IF;
 SELECT * INTO new_lease FROM edr_claim_scan_job('qa-replay','replay','second',
   'dddddddd-dddd-4ddd-8ddd-dddddddddddd',30);
 IF new_lease.job_id IS DISTINCT FROM '88888888-8888-4888-8888-888888888888'::uuid
   OR new_lease.attempt_count IS DISTINCT FROM 2 THEN
   RAISE EXCEPTION 'second lease did not rotate and increment'; END IF;
 IF edr_complete_scan_job('qa-replay','replay',new_lease.job_id,
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',true) THEN
   RAISE EXCEPTION 'stale first lease token replay accepted'; END IF;
 IF NOT EXISTS(SELECT 1 FROM edr_scan_jobs WHERE
   job_id='88888888-8888-4888-8888-888888888888'
   AND state='leased' AND attempt_count=2
   AND lease_token='dddddddd-dddd-4ddd-8ddd-dddddddddddd') THEN
   RAISE EXCEPTION 'replayed token mutated active lease'; END IF;
 IF NOT edr_complete_scan_job('qa-replay','replay',new_lease.job_id,
   'dddddddd-dddd-4ddd-8ddd-dddddddddddd',true) THEN
   RAISE EXCEPTION 'valid second lease completion rejected'; END IF;
 IF edr_complete_scan_job('qa-replay','replay',new_lease.job_id,
   'dddddddd-dddd-4ddd-8ddd-dddddddddddd',true) THEN
   RAISE EXCEPTION 'duplicate completed token accepted'; END IF;
END $recover$;
SQL

# Cleanup our own test fixtures; never run on an existing production DB.
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
DELETE FROM edr_scan_jobs WHERE tenant_id='qa-replay';
DELETE FROM edr_agents WHERE tenant_id='qa-replay';
DELETE FROM edr_tenants WHERE tenant_id='qa-replay';
COMMIT;
SQL
echo 'Post-commit stale token replay and retry exhaustion regression passed'
