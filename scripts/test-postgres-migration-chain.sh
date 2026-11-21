#!/usr/bin/env bash
# Tests the actual 0001..0007 migration order in an EMPTY disposable DB.
set -euo pipefail
: "${EDR_TEST_DATABASE_URL:?Use an empty disposable PostgreSQL database}"
command -v psql >/dev/null

existing="$(psql "$EDR_TEST_DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_class WHERE relname IN ('edr_tenants','edr_agents','edr_agent_certificates','edr_enrollment_audit','edr_enrollment_challenges','edr_scan_jobs') AND relkind='r'")"
if [[ "$existing" != "0" ]]; then
  echo "Refusing to modify a database with existing EDR tables" >&2
  exit 2
fi

for migration in \
  0001_agent_enrollment \
  0002_enrollment_audit_guard \
  0003_certificate_rotation \
  0004_enrollment_challenges \
  0005_scan_job_queue \
  0006_atomic_agent_enrollment \
  0007_scan_job_lease_renewal \
  0008_scan_job_results \
  0009_agent_heartbeats \
  0010_soc_operator_scan_jobs \
  0011_soc_malware_alerts; do
  psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f "backend/migrations/${migration}.up.sql"
done

# Cross-module flow: a single-use authorized enrollment DB transaction,
# certificate rotation/revocation, and a tenant-scoped durable job. This is
# NOT an HTTP endpoint test, CA issuance test, or Windows/Linux agent smoke.
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
INSERT INTO edr_tenants(tenant_id,display_name)
VALUES ('chainA','Migration chain A'),('chainB','Migration chain B');
INSERT INTO edr_enrollment_challenges(
  challenge_id,tenant_id,agent_id,challenge_digest,expires_at)
VALUES (
  '11111111-1111-4111-8111-111111111111','chainA','win01',
  decode(repeat('ab',32),'hex'),now()+interval '5 minutes');
DO $flow$
DECLARE
  ok boolean;
  claimed record;
BEGIN
  ok := edr_complete_agent_enrollment(
    '11111111-1111-4111-8111-111111111111','chainA','win01',
    decode(repeat('ab',32),'hex'),'windows',decode(repeat('cd',32),'hex'),
    now()-interval '1 minute',now()+interval '1 day','chain-issuer');
  IF NOT ok THEN RAISE EXCEPTION 'valid challenge enrollment failed'; END IF;
  IF (SELECT count(*) FROM edr_enrollment_audit
      WHERE tenant_id='chainA' AND agent_id='win01') <> 2 THEN
    RAISE EXCEPTION 'initial enrollment was not audited'; END IF;

  ok := edr_complete_agent_enrollment(
    '11111111-1111-4111-8111-111111111111','chainA','win01',
    decode(repeat('ab',32),'hex'),'windows',decode(repeat('cd',32),'hex'),
    now()-interval '1 minute',now()+interval '1 day','chain-issuer');
  IF ok THEN RAISE EXCEPTION 'enrollment challenge replay accepted'; END IF;

  INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root)
  VALUES ('22222222-2222-4222-8222-222222222222','chainA','win01','C:/Lab');
  SELECT * INTO claimed FROM edr_claim_scan_job(
    'chainB','win01','worker','33333333-3333-4333-8333-333333333333',30);
  IF FOUND THEN RAISE EXCEPTION 'other tenant claimed a scan job'; END IF;
  SELECT * INTO claimed FROM edr_claim_scan_job(
    'chainA','win01','worker','44444444-4444-4444-8444-444444444444',30);
  IF claimed.job_id IS DISTINCT FROM '22222222-2222-4222-8222-222222222222'::uuid
    OR claimed.attempt_count <> 1 THEN
    RAISE EXCEPTION 'enrolled agent did not lease job'; END IF;
  IF NOT edr_renew_scan_job_lease('chainA','win01',claimed.job_id,'worker',
      '44444444-4444-4444-8444-444444444444',30) THEN
    RAISE EXCEPTION 'lease renewal failed in full migration chain'; END IF;
  ok := edr_complete_scan_job(
    'chainA','win01',claimed.job_id,
    '33333333-3333-4333-8333-333333333333',true);
  IF ok THEN RAISE EXCEPTION 'invalid lease token completed job'; END IF;
  ok := edr_complete_scan_job(
    'chainA','win01',claimed.job_id,
    '44444444-4444-4444-8444-444444444444',true);
  IF NOT ok THEN RAISE EXCEPTION 'valid lease completion failed'; END IF;

  -- Malware detection is a completed scan, with durable malicious verdict.
  INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root)
  VALUES ('55555555-5555-4555-8555-555555555555','chainA','win01','C:/Lab/fixture');
  SELECT * INTO claimed FROM edr_claim_scan_job(
    'chainA','win01','worker','66666666-6666-4666-8666-666666666666',30);
  IF claimed.job_id IS DISTINCT FROM '55555555-5555-4555-8555-555555555555'::uuid THEN
    RAISE EXCEPTION 'malware scan lease not claimed'; END IF;
  ok := edr_complete_scan_job_with_result('chainB','win01',claimed.job_id,
    '66666666-6666-4666-8666-666666666666','malicious','Lab-Signature','');
  IF ok THEN RAISE EXCEPTION 'cross-tenant malware completion'; END IF;
  ok := edr_complete_scan_job_with_result('chainA','win01',claimed.job_id,
    '66666666-6666-4666-8666-666666666666','malicious','Lab-Signature','');
  IF NOT ok THEN RAISE EXCEPTION 'valid malware result rejected'; END IF;
  IF (SELECT verdict FROM edr_scan_job_results WHERE job_id=claimed.job_id)
     IS DISTINCT FROM 'malicious' THEN
    RAISE EXCEPTION 'malware result not durably retained'; END IF;
  ok := edr_complete_scan_job_with_result('chainA','win01',claimed.job_id,
    '66666666-6666-4666-8666-666666666666','malicious','Lab-Signature','');
  IF ok THEN RAISE EXCEPTION 'result replay accepted'; END IF;

  ok := edr_rotate_agent_certificate(
    'chainA','win01',decode(repeat('cd',32),'hex'),
    decode(repeat('ef',32),'hex'),
    now()-interval '1 minute',now()+interval '1 day','chain-issuer');
  IF NOT ok THEN RAISE EXCEPTION 'rotation failed after enrollment'; END IF;
  IF (SELECT count(*) FROM edr_agent_certificates
      WHERE tenant_id='chainA' AND agent_id='win01' AND revoked_at IS NULL
        AND not_before<=CURRENT_TIMESTAMP AND not_after>CURRENT_TIMESTAMP) <> 1 THEN
    RAISE EXCEPTION 'rotation left wrong number of active certs'; END IF;
  IF (SELECT count(*) FROM edr_enrollment_audit
      WHERE tenant_id='chainA' AND agent_id='win01') <> 4 THEN
    RAISE EXCEPTION 'rotation audit incomplete'; END IF;

  ok := edr_revoke_agent_certificate(
    'chainA','win01',decode(repeat('ef',32),'hex'),
    'chain-issuer','integration-test');
  IF NOT ok THEN RAISE EXCEPTION 'certificate revocation failed'; END IF;
  IF EXISTS (SELECT 1 FROM edr_agent_certificates
      WHERE tenant_id='chainA' AND agent_id='win01' AND revoked_at IS NULL) THEN
    RAISE EXCEPTION 'revoked cert still active'; END IF;
  IF (SELECT count(*) FROM edr_enrollment_audit
      WHERE tenant_id='chainA' AND agent_id='win01') <> 5 THEN
    RAISE EXCEPTION 'revocation audit missing'; END IF;

  BEGIN
    UPDATE edr_enrollment_audit SET actor_id='tampered'
    WHERE tenant_id='chainA' AND agent_id='win01';
    RAISE EXCEPTION 'audit mutation unexpectedly accepted';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END $flow$;
ROLLBACK;
SQL
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f scripts/test-agent-heartbeats.sql
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f scripts/test-soc-scheduling.sql
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f scripts/test-soc-alerts.sql
echo "Full PostgreSQL migration chain (0001..0011) integration passed"
