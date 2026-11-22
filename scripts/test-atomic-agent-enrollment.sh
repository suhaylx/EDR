#!/usr/bin/env bash
set -euo pipefail
: "${EDR_TEST_DATABASE_URL:?Set a disposable PostgreSQL connection URL}"
for n in 0001_agent_enrollment 0004_enrollment_challenges 0006_atomic_agent_enrollment; do
  psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f "backend/migrations/${n}.up.sql"
done
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
INSERT INTO edr_tenants(tenant_id,display_name)
VALUES('tenantA','Tenant A'),('tenantB','Tenant B');
INSERT INTO edr_enrollment_challenges(challenge_id,tenant_id,agent_id,challenge_digest,expires_at)
VALUES
('11111111-1111-4111-8111-111111111111','tenantA','win01',decode(repeat('ab',32),'hex'),now()+interval '5 minutes'),
('22222222-2222-4222-8222-222222222222','tenantB','win01',decode(repeat('cd',32),'hex'),now()+interval '5 minutes');
DO $$
DECLARE
    ok boolean;
BEGIN
    ok:=edr_complete_agent_enrollment(
        '11111111-1111-4111-8111-111111111111','tenantB','win01',
        decode(repeat('ab',32),'hex'),'windows',decode(repeat('ef',32),'hex'),
        now()-interval '1 minute',now()+interval '1 day','issuer-test');
    IF ok THEN RAISE EXCEPTION 'cross-tenant challenge accepted'; END IF;
    ok:=edr_complete_agent_enrollment(
        '11111111-1111-4111-8111-111111111111','tenantA','win01',
        decode(repeat('ab',32),'hex'),'windows',decode(repeat('ef',32),'hex'),
        now()-interval '1 minute',now()+interval '1 day','issuer-test');
    IF NOT ok THEN RAISE EXCEPTION 'valid enrollment rejected'; END IF;
    ok:=edr_complete_agent_enrollment(
        '11111111-1111-4111-8111-111111111111','tenantA','win01',
        decode(repeat('ab',32),'hex'),'windows',decode(repeat('ef',32),'hex'),
        now()-interval '1 minute',now()+interval '1 day','issuer-test');
    IF ok THEN RAISE EXCEPTION 'challenge replay accepted'; END IF;
    IF (SELECT count(*) FROM edr_enrollment_audit
        WHERE tenant_id='tenantA' AND agent_id='win01')<>2 THEN
        RAISE EXCEPTION 'expected both audit records'; END IF;
    IF (SELECT count(*) FROM edr_agent_certificates
        WHERE tenant_id='tenantA' AND agent_id='win01')<>1 THEN
        RAISE EXCEPTION 'expected one certificate'; END IF;
    UPDATE edr_tenants SET disabled_at=now() WHERE tenant_id='tenantB';
    ok:=edr_complete_agent_enrollment(
        '22222222-2222-4222-8222-222222222222','tenantB','win01',
        decode(repeat('cd',32),'hex'),'windows',decode(repeat('ef',32),'hex'),
        now()-interval '1 minute',now()+interval '1 day','issuer-test');
    IF ok THEN RAISE EXCEPTION 'disabled tenant enrolled'; END IF;
    IF EXISTS(SELECT 1 FROM edr_agents WHERE tenant_id='tenantB') THEN
        RAISE EXCEPTION 'disabled tenant created an agent'; END IF;
END $$;
ROLLBACK;
SQL
echo "Atomic agent enrollment integration passed"
