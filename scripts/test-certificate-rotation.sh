#!/usr/bin/env bash
# Run ONLY on an empty disposable PostgreSQL database.
set -euo pipefail
: "${EDR_TEST_DATABASE_URL:?Use a disposable PostgreSQL database}"
command -v psql >/dev/null
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f backend/migrations/0001_agent_enrollment.up.sql
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f backend/migrations/0002_enrollment_audit_guard.up.sql
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f backend/migrations/0003_certificate_rotation.up.sql
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
INSERT INTO edr_tenants(tenant_id,display_name) VALUES ('tenantA','A'),('tenantB','B');
INSERT INTO edr_agents(tenant_id,agent_id,platform) VALUES
('tenantA','win01','windows'),('tenantB','win01','windows'),('tenantA','linux01','linux');
INSERT INTO edr_agent_certificates(tenant_id,agent_id,fingerprint_sha256,not_before,not_after)
VALUES ('tenantA','win01',decode(repeat('aa',32),'hex'),now()-interval '1 hour',now()+interval '1 day'),
       ('tenantB','win01',decode(repeat('aa',32),'hex'),now()-interval '1 hour',now()+interval '1 day'),
       ('tenantA','linux01',decode(repeat('dd',32),'hex'),now()-interval '1 hour',now()+interval '1 day');
DO $$
DECLARE ok boolean;
BEGIN
  ok := edr_rotate_agent_certificate('tenantA','win01',decode(repeat('aa',32),'hex'),
      decode(repeat('bb',32),'hex'),now()-interval '1 minute',now()+interval '1 day','soc-operator');
  IF NOT ok THEN RAISE EXCEPTION 'expected rotation'; END IF;
  IF (SELECT count(*) FROM edr_agent_certificates WHERE tenant_id='tenantA'
      AND agent_id='win01' AND revoked_at IS NULL) <> 1 THEN
      RAISE EXCEPTION 'rotation left wrong number of active leaves'; END IF;
  IF (SELECT count(*) FROM edr_enrollment_audit WHERE tenant_id='tenantA'
      AND agent_id='win01') <> 2 THEN RAISE EXCEPTION 'rotation audit incomplete'; END IF;
  IF (SELECT count(*) FROM edr_agent_certificates WHERE tenant_id='tenantB'
      AND revoked_at IS NULL) <> 1 THEN RAISE EXCEPTION 'cross-tenant mutation'; END IF;
  ok := edr_rotate_agent_certificate('tenantA','win01',decode(repeat('aa',32),'hex'),
      decode(repeat('cc',32),'hex'),now()-interval '1 minute',now()+interval '1 day','soc-operator');
  IF ok THEN RAISE EXCEPTION 'stale rotation replay accepted'; END IF;
  ok := edr_rotate_agent_certificate('tenantB','win01',decode(repeat('bb',32),'hex'),
      decode(repeat('cc',32),'hex'),now()-interval '1 minute',now()+interval '1 day','soc-operator');
  IF ok THEN RAISE EXCEPTION 'wrong tenant leaf accepted'; END IF;
  BEGIN
    PERFORM edr_rotate_agent_certificate('tenantA','win01',decode(repeat('bb',32),'hex'),
      decode(repeat('cc',32),'hex'),now()+interval '1 day',now(),'soc-operator');
    RAISE EXCEPTION 'invalid dates accepted';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
  BEGIN
    PERFORM edr_rotate_agent_certificate('tenantA','win01',decode(repeat('bb',32),'hex'),
      decode(repeat('cc',32),'hex'),now(),now()+interval '1 day','');
    RAISE EXCEPTION 'missing actor accepted';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
END $$;
UPDATE edr_tenants SET disabled_at=now() WHERE tenant_id='tenantA';
DO $$
BEGIN
  IF edr_rotate_agent_certificate('tenantA','win01',decode(repeat('bb',32),'hex'),
      decode(repeat('cc',32),'hex'),now(),now()+interval '1 day','soc-operator') THEN
    RAISE EXCEPTION 'disabled tenant rotation accepted';
  END IF;
END $$;
ROLLBACK;
SQL
echo "PostgreSQL certificate rotation integration passed"
