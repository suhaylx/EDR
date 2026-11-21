#!/usr/bin/env bash
# Disposable empty PostgreSQL database only.
set -euo pipefail
: "${EDR_TEST_DATABASE_URL:?Set a disposable PostgreSQL connection URL}"
command -v psql >/dev/null
existing="$(psql "$EDR_TEST_DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_class WHERE relname IN ('edr_tenants','edr_agents','edr_agent_certificates','edr_scan_jobs') AND relkind='r'")"
if [[ "$existing" != "0" ]]; then
  echo "Refusing to run: EDR tables already exist; use an empty disposable database" >&2
  exit 2
fi
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
UPDATE edr_tenants SET disabled_at=now() WHERE tenant_id='tenantB';
DO $$
BEGIN
  IF EXISTS(SELECT 1 FROM edr_claim_scan_job('tenantB','win01','agent-win01',
    'dddddddd-dddd-4ddd-8ddd-dddddddddddd',30)) THEN
    RAISE EXCEPTION 'disabled tenant received a job'; END IF;
END $$;
-- An active lease does not bypass subsequent principal revocation.
INSERT INTO edr_agents(tenant_id,agent_id,platform)
VALUES ('tenantA','revoked-agent','linux'),('tenantA','disabled-agent','linux');
INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root)
VALUES ('33333333-3333-4333-8333-333333333333','tenantA','revoked-agent','/tmp/test'),
       ('44444444-4444-4444-8444-444444444444','tenantA','disabled-agent','/tmp/test');
DO $revoked_agent$
DECLARE leased record;
BEGIN
  SELECT * INTO leased FROM edr_claim_scan_job('tenantA','revoked-agent','test',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',30);
  IF leased.job_id IS DISTINCT FROM '33333333-3333-4333-8333-333333333333'::uuid
    THEN RAISE EXCEPTION 'revocation fixture claim failed'; END IF;
  UPDATE edr_agents SET revoked_at=CURRENT_TIMESTAMP
    WHERE tenant_id='tenantA' AND agent_id='revoked-agent';
  IF edr_complete_scan_job('tenantA','revoked-agent',leased.job_id,
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',true)
    THEN RAISE EXCEPTION 'revoked agent completed job'; END IF;
  IF (SELECT state FROM edr_scan_jobs WHERE job_id=leased.job_id) <> 'leased'
    THEN RAISE EXCEPTION 'failed completion changed leased job'; END IF;
END $revoked_agent$;
DO $disabled_tenant$
DECLARE leased record;
BEGIN
  SELECT * INTO leased FROM edr_claim_scan_job('tenantA','disabled-agent','test',
    'ffffffff-ffff-4fff-8fff-ffffffffffff',30);
  IF leased.job_id IS DISTINCT FROM '44444444-4444-4444-8444-444444444444'::uuid
    THEN RAISE EXCEPTION 'disable fixture claim failed'; END IF;
  UPDATE edr_tenants SET disabled_at=CURRENT_TIMESTAMP WHERE tenant_id='tenantA';
  IF edr_complete_scan_job('tenantA','disabled-agent',leased.job_id,
    'ffffffff-ffff-4fff-8fff-ffffffffffff',true)
    THEN RAISE EXCEPTION 'disabled tenant completed job'; END IF;
  IF (SELECT state FROM edr_scan_jobs WHERE job_id=leased.job_id) <> 'leased'
    THEN RAISE EXCEPTION 'failed completion changed leased job'; END IF;
END $disabled_tenant$;
ROLLBACK;
SQL
echo "Durable scan-job queue integration passed"
