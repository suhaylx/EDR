#!/usr/bin/env bash
# Run after test-scan-job-queue.sh against the same disposable PostgreSQL DB.
# This checks COMMITTED revocation/tenant disablement across separate sessions.
set -euo pipefail
: "${EDR_TEST_DATABASE_URL:?Set a disposable PostgreSQL connection URL}"
command -v psql >/dev/null

# Session 1: authenticate/claim while both principals are still active.
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
INSERT INTO edr_tenants(tenant_id,display_name)
VALUES ('qa-revoked','Revocation test'),('qa-disabled','Tenant disable test');
INSERT INTO edr_agents(tenant_id,agent_id,platform)
VALUES ('qa-revoked','win01','windows'),('qa-disabled','linux01','linux');
INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root)
VALUES
 ('ac555555-5555-4555-8555-555555555555','qa-revoked','win01','C:/Test'),
 ('bc666666-6666-4666-8666-666666666666','qa-disabled','linux01','/tmp/test');
DO $claim$
DECLARE
  a record;
  b record;
BEGIN
  SELECT * INTO a FROM edr_claim_scan_job('qa-revoked','win01','qa-worker',
    '77777777-7777-4777-8777-777777777777',300);
  SELECT * INTO b FROM edr_claim_scan_job('qa-disabled','linux01','qa-worker',
    '88888888-8888-4888-8888-888888888888',300);
  IF a.job_id IS DISTINCT FROM 'ac555555-5555-4555-8555-555555555555'::uuid
    OR a.attempt_count IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'revocation fixture was not claimed';
  END IF;
  IF b.job_id IS DISTINCT FROM 'bc666666-6666-4666-8666-666666666666'::uuid
    OR b.attempt_count IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'tenant disable fixture was not claimed';
  END IF;
END $claim$;
COMMIT;
SQL

# Session 2: change authorization and COMMIT before completion is attempted.
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
UPDATE edr_agents SET revoked_at=clock_timestamp()
WHERE tenant_id='qa-revoked' AND agent_id='win01';
UPDATE edr_tenants SET disabled_at=clock_timestamp()
WHERE tenant_id='qa-disabled';
COMMIT;
SQL

# Session 3: both success and failure reports must be denied without mutation.
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
DO $verify$
BEGIN
  IF edr_complete_scan_job('qa-revoked','win01',
    'ac555555-5555-4555-8555-555555555555',
    '77777777-7777-4777-8777-777777777777',true) THEN
    RAISE EXCEPTION 'revoked agent reported success after commit';
  END IF;
  IF edr_complete_scan_job('qa-revoked','win01',
    'ac555555-5555-4555-8555-555555555555',
    '77777777-7777-4777-8777-777777777777',false) THEN
    RAISE EXCEPTION 'revoked agent reported failure after commit';
  END IF;
  IF edr_complete_scan_job('qa-disabled','linux01',
    'bc666666-6666-4666-8666-666666666666',
    '88888888-8888-4888-8888-888888888888',true) THEN
    RAISE EXCEPTION 'disabled tenant reported success after commit';
  END IF;
  IF edr_complete_scan_job('qa-disabled','linux01',
    'bc666666-6666-4666-8666-666666666666',
    '88888888-8888-4888-8888-888888888888',false) THEN
    RAISE EXCEPTION 'disabled tenant reported failure after commit';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM edr_scan_jobs WHERE
      job_id='ac555555-5555-4555-8555-555555555555'
      AND state='leased' AND attempt_count=1
      AND lease_token='77777777-7777-4777-8777-777777777777'
  ) THEN RAISE EXCEPTION 'revoked lease was unexpectedly changed'; END IF;
  IF NOT EXISTS (
    SELECT 1 FROM edr_scan_jobs WHERE
      job_id='bc666666-6666-4666-8666-666666666666'
      AND state='leased' AND attempt_count=1
      AND lease_token='88888888-8888-4888-8888-888888888888'
  ) THEN RAISE EXCEPTION 'disabled-tenant lease was unexpectedly changed'; END IF;
END $verify$;
SQL

echo "Post-commit scan-job revocation and tenant disablement checks passed"
