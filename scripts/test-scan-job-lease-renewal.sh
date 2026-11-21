#!/usr/bin/env bash
# Disposable database only; run after test-scan-job-queue.sh has created schema.
set -euo pipefail
: "${EDR_TEST_DATABASE_URL:?Set disposable PostgreSQL URL}"
command -v psql >/dev/null
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f backend/migrations/0007_scan_job_lease_renewal.up.sql
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
INSERT INTO edr_tenants(tenant_id,display_name) VALUES ('renewA','Renew A'),('renewB','Renew B');
INSERT INTO edr_agents(tenant_id,agent_id,platform) VALUES ('renewA','device','linux'),('renewB','device','linux');
INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root)
VALUES ('77777777-7777-4777-8777-777777777777','renewA','device','/tmp/fixture');
DO $test$
DECLARE
  claimed record;
  before_expiry timestamptz;
BEGIN
  -- Claim a shorter lease, then renew to 30s in the same transaction.
  -- Both functions use transaction_timestamp(), so claiming and renewing
  -- for the *same* TTL inside a single transaction cannot extend expiry.
  -- A 10s -> 30s change demonstrates real extension without weakening the
  -- rejection tests for wrong tenant/worker/token, expiry or revocation.
  SELECT * INTO claimed FROM edr_claim_scan_job('renewA','device','worker1',
    '88888888-8888-4888-8888-888888888888',10);
  IF claimed.job_id IS NULL THEN RAISE EXCEPTION 'claim failed'; END IF;
  SELECT lease_expires_at INTO before_expiry FROM edr_scan_jobs WHERE job_id=claimed.job_id;
  IF edr_renew_scan_job_lease('renewB','device',claimed.job_id,'worker1',
    '88888888-8888-4888-8888-888888888888',30) THEN
    RAISE EXCEPTION 'cross tenant renewal'; END IF;
  IF edr_renew_scan_job_lease('renewA','device',claimed.job_id,'other',
    '88888888-8888-4888-8888-888888888888',30) THEN
    RAISE EXCEPTION 'wrong worker renewal'; END IF;
  IF edr_renew_scan_job_lease('renewA','device',claimed.job_id,'worker1',
    '99999999-9999-4999-8999-999999999999',30) THEN
    RAISE EXCEPTION 'wrong token renewal'; END IF;
  IF edr_renew_scan_job_lease('renewA','device',claimed.job_id,'worker1',
    '88888888-8888-4888-8888-888888888888',301) THEN
    RAISE EXCEPTION 'unbounded renewal'; END IF;
  IF NOT edr_renew_scan_job_lease('renewA','device',claimed.job_id,'worker1',
    '88888888-8888-4888-8888-888888888888',30) THEN
    RAISE EXCEPTION 'valid renewal rejected'; END IF;
  IF (SELECT lease_expires_at FROM edr_scan_jobs WHERE job_id=claimed.job_id)
       <= before_expiry THEN RAISE EXCEPTION 'expiry not extended'; END IF;
  IF (SELECT lease_expires_at FROM edr_scan_jobs WHERE job_id=claimed.job_id)
       > transaction_timestamp()+interval '31 seconds' THEN
    RAISE EXCEPTION 'renewal accumulates unbounded time'; END IF;
  UPDATE edr_agents SET revoked_at=now() WHERE tenant_id='renewA' AND agent_id='device';
  IF edr_renew_scan_job_lease('renewA','device',claimed.job_id,'worker1',
    '88888888-8888-4888-8888-888888888888',30) THEN
    RAISE EXCEPTION 'revoked device renewal'; END IF;
  UPDATE edr_agents SET revoked_at=NULL WHERE tenant_id='renewA' AND agent_id='device';
  UPDATE edr_tenants SET disabled_at=now() WHERE tenant_id='renewA';
  IF edr_renew_scan_job_lease('renewA','device',claimed.job_id,'worker1',
    '88888888-8888-4888-8888-888888888888',30) THEN
    RAISE EXCEPTION 'disabled tenant renewed lease'; END IF;
  UPDATE edr_tenants SET disabled_at=NULL WHERE tenant_id='renewA';
  IF NOT edr_complete_scan_job('renewA','device',claimed.job_id,
      '88888888-8888-4888-8888-888888888888',true) THEN
    RAISE EXCEPTION 'completion precondition failed'; END IF;
  IF edr_renew_scan_job_lease('renewA','device',claimed.job_id,'worker1',
      '88888888-8888-4888-8888-888888888888',30) THEN
    RAISE EXCEPTION 'completed job renewed'; END IF;
  UPDATE edr_scan_jobs SET state='leased',lease_owner='worker1',
    lease_token='88888888-8888-4888-8888-888888888888',
    lease_expires_at=now()+interval '30 seconds' WHERE job_id=claimed.job_id;
  UPDATE edr_scan_jobs SET lease_expires_at=now()-interval '1 second'
    WHERE job_id=claimed.job_id;
  IF edr_renew_scan_job_lease('renewA','device',claimed.job_id,'worker1',
    '88888888-8888-4888-8888-888888888888',30) THEN
    RAISE EXCEPTION 'expired lease renewed'; END IF;
  IF edr_recover_expired_scan_jobs(10) <> 1 THEN
    RAISE EXCEPTION 'expired lease not recovered'; END IF;
  IF edr_renew_scan_job_lease('renewA','device',claimed.job_id,'worker1',
    '88888888-8888-4888-8888-888888888888',30) THEN
    RAISE EXCEPTION 'requeued lease renewed'; END IF;
END $test$;
ROLLBACK;
SQL
echo "Lease renewal negative/positive SQL tests passed"
