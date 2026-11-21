#!/usr/bin/env bash
# Disposable empty PostgreSQL database only.
set -euo pipefail
: "${EDR_TEST_DATABASE_URL:?Set a disposable PostgreSQL connection URL}"
command -v psql >/dev/null
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f backend/migrations/0001_agent_enrollment.up.sql
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f backend/migrations/0005_scan_job_queue.up.sql
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
INSERT INTO edr_tenants(tenant_id,display_name) VALUES ('tenantA','A'),('tenantB','B');
INSERT INTO edr_agents(tenant_id,agent_id,platform) VALUES ('tenantA','win01','windows'),('tenantB','win01','windows');
INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root)
VALUES ('11111111-1111-4111-8111-111111111111','tenantA','win01','C:/Lab'),
       ('22222222-2222-4222-8222-222222222222','tenantB','win01','/lab');
DO $$
DECLARE
  claimed record;
  ok boolean;
BEGIN
  SELECT * INTO claimed FROM edr_claim_scan_job('tenantA','win01','agent-win01',
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',30);
  IF claimed.job_id IS DISTINCT FROM '11111111-1111-4111-8111-111111111111'::uuid
     OR claimed.attempt_count <> 1 THEN RAISE EXCEPTION 'wrong job claimed'; END IF;
  IF EXISTS(SELECT 1 FROM edr_claim_scan_job('tenantA','win01','agent-win01',
    'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',30)) THEN
    RAISE EXCEPTION 'leased job claimed twice'; END IF;
  ok := edr_complete_scan_job('tenantB','win01',claimed.job_id,
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',true);
  IF ok THEN RAISE EXCEPTION 'cross-tenant completion accepted'; END IF;
  ok := edr_complete_scan_job('tenantA','win01',claimed.job_id,
    'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',true);
  IF ok THEN RAISE EXCEPTION 'wrong token completion accepted'; END IF;
  ok := edr_complete_scan_job('tenantA','win01',claimed.job_id,
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',true);
  IF NOT ok THEN RAISE EXCEPTION 'valid completion rejected'; END IF;
  ok := edr_complete_scan_job('tenantA','win01',claimed.job_id,
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',true);
  IF ok THEN RAISE EXCEPTION 'duplicate completion accepted'; END IF;
END $$;
UPDATE edr_scan_jobs SET state='leased',lease_owner='old-worker',
 lease_token='cccccccc-cccc-4ccc-8ccc-cccccccccccc',
 lease_expires_at=now()-interval '1 second',attempt_count=1
WHERE tenant_id='tenantB';
DO $$
BEGIN
  IF edr_recover_expired_scan_jobs(10) <> 1 THEN
    RAISE EXCEPTION 'expired job not recovered'; END IF;
  IF (SELECT state FROM edr_scan_jobs WHERE tenant_id='tenantB') <> 'pending' THEN
    RAISE EXCEPTION 'expired job not requeued'; END IF;
END $$;
-- QA P0: isolate replay fixture on a dedicated agent so the existing
-- expired-job recovery assertion remains deterministic.
INSERT INTO edr_agents(tenant_id,agent_id,platform)
VALUES ('tenantA','qa-replay','linux'),('tenantA','qa-other','linux');
INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root)
VALUES ('55555555-5555-4555-8555-555555555555','tenantA','qa-replay','/replay');
DO $replay$
DECLARE
  job uuid := '55555555-5555-4555-8555-555555555555';
  first_token uuid := '11111111-aaaa-4111-8111-111111111111';
  next_token uuid := '22222222-bbbb-4222-8222-222222222222';
  leased record;
BEGIN
  SELECT * INTO leased FROM edr_claim_scan_job('tenantA','qa-replay','worker-1',first_token,30);
  IF leased.job_id IS DISTINCT FROM job THEN
    RAISE EXCEPTION 'initial replay fixture claim failed'; END IF;
  UPDATE edr_scan_jobs SET lease_expires_at=transaction_timestamp()-interval '1 second'
    WHERE job_id=job;
  IF edr_complete_scan_job('tenantA','qa-other',job,first_token,true) THEN
    RAISE EXCEPTION 'same-tenant wrong-agent completion accepted'; END IF;
  IF edr_complete_scan_job('tenantA','qa-replay',job,first_token,true) THEN
    RAISE EXCEPTION 'expired lease completion accepted'; END IF;
  IF (SELECT state FROM edr_scan_jobs WHERE job_id=job) <> 'leased' THEN
    RAISE EXCEPTION 'expired completion mutated job'; END IF;
  IF edr_recover_expired_scan_jobs(10) <> 1 THEN
    RAISE EXCEPTION 'replay fixture recovery failed'; END IF;
  SELECT * INTO leased FROM edr_claim_scan_job('tenantA','qa-replay','worker-2',next_token,30);
  IF leased.job_id IS DISTINCT FROM job OR leased.attempt_count <> 2 THEN
    RAISE EXCEPTION 'recovered lease not issued'; END IF;
  IF edr_complete_scan_job('tenantA','qa-replay',job,first_token,true) THEN
    RAISE EXCEPTION 'stale token replay accepted'; END IF;
  IF (SELECT state FROM edr_scan_jobs WHERE job_id=job) <> 'leased' THEN
    RAISE EXCEPTION 'replay mutated active lease'; END IF;
  IF NOT edr_complete_scan_job('tenantA','qa-replay',job,next_token,false) THEN
    RAISE EXCEPTION 'valid recovered completion rejected'; END IF;
  IF (SELECT state FROM edr_scan_jobs WHERE job_id=job) <> 'failed' THEN
    RAISE EXCEPTION 'failed result state not persisted'; END IF;
END $replay$;
-- Exhausted retry budget must fail the job rather than requeue forever.
INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root,max_attempts)
VALUES ('66666666-6666-4666-8666-666666666666','tenantA','qa-replay','/exhausted',1);
DO $exhausted$
DECLARE
  job uuid := '66666666-6666-4666-8666-666666666666';
  leased record;
BEGIN
  SELECT * INTO leased FROM edr_claim_scan_job('tenantA','qa-replay','worker-3',
    '33333333-cccc-4333-8333-333333333333',30);
  IF leased.job_id IS DISTINCT FROM job OR leased.attempt_count <> 1 THEN
    RAISE EXCEPTION 'retry-budget fixture claim failed'; END IF;
  UPDATE edr_scan_jobs SET lease_expires_at=transaction_timestamp()-interval '1 second'
    WHERE job_id=job;
  IF edr_recover_expired_scan_jobs(10) <> 1 THEN
    RAISE EXCEPTION 'exhausted job not recovered'; END IF;
  IF (SELECT state FROM edr_scan_jobs WHERE job_id=job) <> 'failed' THEN
    RAISE EXCEPTION 'exhausted job requeued'; END IF;
  IF EXISTS(SELECT 1 FROM edr_claim_scan_job('tenantA','qa-replay','worker-4',
    '44444444-dddd-4444-8444-444444444444',30)) THEN
    RAISE EXCEPTION 'exhausted job claimed again'; END IF;
END $exhausted$;
UPDATE edr_tenants SET disabled_at=now() WHERE tenant_id='tenantB';
DO $$
BEGIN
  IF EXISTS(SELECT 1 FROM edr_claim_scan_job('tenantB','win01','agent-win01',
    'dddddddd-dddd-4ddd-8ddd-dddddddddddd',30)) THEN
    RAISE EXCEPTION 'disabled tenant received a job'; END IF;
END $$;

-- Invalid inputs must fail closed without consuming or modifying jobs.
DO $invalid_parameters$
BEGIN
  IF edr_complete_scan_job(NULL,'win01',
    '11111111-1111-4111-8111-111111111111',
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',true) THEN
    RAISE EXCEPTION 'NULL tenant completion accepted'; END IF;
  IF edr_complete_scan_job('tenantA','win01',
    '11111111-1111-4111-8111-111111111111',NULL,true) THEN
    RAISE EXCEPTION 'NULL token completion accepted'; END IF;
  BEGIN
    PERFORM edr_claim_scan_job('tenantA','win01','qa',
      '77777777-7777-4777-8777-777777777777',4);
    RAISE EXCEPTION 'too-short lease accepted';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
  BEGIN
    PERFORM edr_recover_expired_scan_jobs(0);
    RAISE EXCEPTION 'zero recovery limit accepted';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
  BEGIN
    PERFORM edr_recover_expired_scan_jobs(1001);
    RAISE EXCEPTION 'oversized recovery limit accepted';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
END $invalid_parameters$;

-- A live lease is not valid evidence of current authorization. Revoke or
-- disable the principal *after* claiming, and ensure completion is refused.
INSERT INTO edr_agents(tenant_id,agent_id,platform)
VALUES ('tenantA','revoked-agent','linux'),('tenantA','disabled-agent','linux');
INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root)
VALUES
 ('33333333-3333-4333-8333-333333333333','tenantA','revoked-agent','/tmp/test'),
 ('44444444-4444-4444-8444-444444444444','tenantA','disabled-agent','/tmp/test');
DO $revoke_agent$
DECLARE leased record;
BEGIN
  SELECT * INTO leased FROM edr_claim_scan_job('tenantA','revoked-agent','qa',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',30);
  IF leased.job_id IS DISTINCT FROM '33333333-3333-4333-8333-333333333333'::uuid
    THEN RAISE EXCEPTION 'could not claim revocation test job'; END IF;
  UPDATE edr_agents SET revoked_at=now()
    WHERE tenant_id='tenantA' AND agent_id='revoked-agent';
  IF edr_complete_scan_job('tenantA','revoked-agent',leased.job_id,
      'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',true)
    THEN RAISE EXCEPTION 'revoked agent completed a leased job'; END IF;
  IF (SELECT state FROM edr_scan_jobs WHERE job_id=leased.job_id) <> 'leased'
    THEN RAISE EXCEPTION 'rejected completion mutated job'; END IF;
END $revoke_agent$;
DO $disable_tenant$
DECLARE leased record;
BEGIN
  SELECT * INTO leased FROM edr_claim_scan_job('tenantA','disabled-agent','qa',
    'ffffffff-ffff-4fff-8fff-ffffffffffff',30);
  IF leased.job_id IS DISTINCT FROM '44444444-4444-4444-8444-444444444444'::uuid
    THEN RAISE EXCEPTION 'could not claim tenant-disable test job'; END IF;
  UPDATE edr_tenants SET disabled_at=now() WHERE tenant_id='tenantA';
  IF edr_complete_scan_job('tenantA','disabled-agent',leased.job_id,
      'ffffffff-ffff-4fff-8fff-ffffffffffff',true)
    THEN RAISE EXCEPTION 'disabled tenant completed a leased job'; END IF;
  IF (SELECT state FROM edr_scan_jobs WHERE job_id=leased.job_id) <> 'leased'
    THEN RAISE EXCEPTION 'rejected completion mutated job'; END IF;
END $disable_tenant$;
ROLLBACK;
SQL
echo "Durable scan-job queue integration passed"
