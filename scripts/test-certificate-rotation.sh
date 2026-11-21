#!/usr/bin/env bash
# Run ONLY on an empty disposable PostgreSQL database.
set -euo pipefail
: "${EDR_TEST_DATABASE_URL:?Use a disposable PostgreSQL database}"
command -v psql >/dev/null
existing="$(psql "$EDR_TEST_DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_class WHERE relname IN ('edr_tenants','edr_agents','edr_agent_certificates','edr_enrollment_audit') AND relkind='r'")"
if [[ "$existing" != "0" ]]; then
  echo "Refusing to modify database with existing EDR tables; use empty disposable PostgreSQL" >&2
  exit 2
fi
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

-- Rotation must not revoke a working leaf to install one outside the
-- authoritative database enrollment window. Both time boundaries are exact.
DO $window$
DECLARE
  ok boolean;
BEGIN
  BEGIN
    PERFORM edr_rotate_agent_certificate('tenantA','win01',
      decode(repeat('bb',32),'hex'),decode(repeat('cc',32),'hex'),
      CURRENT_TIMESTAMP + interval '1 second',CURRENT_TIMESTAMP + interval '1 day',
      'soc-operator');
    RAISE EXCEPTION 'future-dated rotation accepted';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
  BEGIN
    PERFORM edr_rotate_agent_certificate('tenantA','win01',
      decode(repeat('bb',32),'hex'),decode(repeat('cc',32),'hex'),
      CURRENT_TIMESTAMP - interval '2 days',CURRENT_TIMESTAMP - interval '1 second',
      'soc-operator');
    RAISE EXCEPTION 'expired rotation accepted';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
  BEGIN
    PERFORM edr_rotate_agent_certificate('tenantA','win01',
      decode(repeat('bb',32),'hex'),decode(repeat('cc',32),'hex'),
      CURRENT_TIMESTAMP - interval '1 day',CURRENT_TIMESTAMP,
      'soc-operator');
    RAISE EXCEPTION 'exact expiry boundary accepted';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
  IF (SELECT count(*) FROM edr_agent_certificates
      WHERE tenant_id='tenantA' AND agent_id='win01' AND revoked_at IS NULL
        AND fingerprint_sha256=decode(repeat('bb',32),'hex'))<>1 THEN
    RAISE EXCEPTION 'rejected rotation changed current certificate'; END IF;
  IF (SELECT count(*) FROM edr_enrollment_audit
      WHERE tenant_id='tenantA' AND agent_id='win01')<>2 THEN
    RAISE EXCEPTION 'rejected rotation wrote audit records'; END IF;
  -- The exact not_before boundary is inclusive.
  ok:=edr_rotate_agent_certificate('tenantA','win01',
      decode(repeat('bb',32),'hex'),decode(repeat('cc',32),'hex'),
      CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+interval '1 day','soc-operator');
  IF NOT ok THEN RAISE EXCEPTION 'inclusive start boundary rejected'; END IF;
END $window$;

UPDATE edr_tenants SET disabled_at=now() WHERE tenant_id='tenantA';
DO $$
BEGIN
  IF edr_rotate_agent_certificate('tenantA','win01',decode(repeat('cc',32),'hex'),
      decode(repeat('ee',32),'hex'),now(),now()+interval '1 day','soc-operator') THEN
    RAISE EXCEPTION 'disabled tenant rotation accepted';
  END IF;
END $$;
ROLLBACK;
SQL
# Cross-connection race: tenant disablement holds the tenant row lock.
# Rotation MUST wait for that transaction to commit and return false, without
# revoking the previously active leaf or producing spurious audit entries.
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
INSERT INTO edr_tenants(tenant_id,display_name) VALUES ('raceTenant','Race tenant');
INSERT INTO edr_agents(tenant_id,agent_id,platform)
  VALUES ('raceTenant','win01','windows');
INSERT INTO edr_agent_certificates(
  tenant_id,agent_id,fingerprint_sha256,not_before,not_after)
  VALUES ('raceTenant','win01',decode(repeat('aa',32),'hex'),
          now()-interval '1 hour',now()+interval '1 day');
SQL
PGAPPNAME=edr-rotation-ci-disable psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL' >/dev/null 2>&1 &
BEGIN;
UPDATE edr_tenants SET disabled_at=clock_timestamp()
WHERE tenant_id='raceTenant';
SELECT pg_sleep(3);
COMMIT;
SQL
disabler_pid=$!
ready=0
for _ in $(seq 1 60); do
  activity="$(psql "$EDR_TEST_DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_stat_activity WHERE application_name='edr-rotation-ci-disable' AND state='active' AND query LIKE '%pg_sleep(3)%'")"
  if [[ "$activity" == "1" ]]; then ready=1; break; fi
  sleep 0.1
done
if [[ "$ready" != "1" ]]; then
  wait "$disabler_pid" || true
  echo "Failed to establish disablement/rotation race fixture" >&2
  exit 1
fi
rotated="$(psql "$EDR_TEST_DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c "SET statement_timeout='10s'; SELECT edr_rotate_agent_certificate('raceTenant','win01',decode(repeat('aa',32),'hex'),decode(repeat('bb',32),'hex'),now(),now()+interval '1 day','race-issuer')")"
wait "$disabler_pid"
if [[ "$(printf '%s\n' "$rotated" | tail -n 1)" != "f" ]]; then
  echo "Rotation authorization race: disabled tenant was rotated" >&2
  exit 1
fi
safe="$(psql "$EDR_TEST_DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM edr_agent_certificates WHERE tenant_id='raceTenant' AND agent_id='win01' AND revoked_at IS NULL AND fingerprint_sha256=decode(repeat('aa',32),'hex')")"
if [[ "$safe" != "1" ]]; then
  echo "Rotation authorization race: original certificate was altered" >&2
  exit 1
fi
audits="$(psql "$EDR_TEST_DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM edr_enrollment_audit WHERE tenant_id='raceTenant'")"
if [[ "$audits" != "0" ]]; then
  echo "Rotation authorization race: denial produced audit records" >&2
  exit 1
fi
echo "PostgreSQL certificate rotation integration passed"
