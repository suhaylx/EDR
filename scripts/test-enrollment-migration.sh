#!/usr/bin/env bash
# Run against an isolated, disposable PostgreSQL database only.
# Usage: EDR_TEST_DATABASE_URL='postgresql://...' bash scripts/test-enrollment-migration.sh
# Requires psql and a database role permitted to create/drop tables.
set -euo pipefail

if [[ -z "${EDR_TEST_DATABASE_URL:-}" ]]; then
  echo "EDR_TEST_DATABASE_URL is required (use a disposable database)" >&2
  exit 2
fi
if ! command -v psql >/dev/null 2>&1; then
  echo "psql is required" >&2
  exit 2
fi

# This script assumes an EMPTY disposable database. Never point at production.
existing="$(psql "$EDR_TEST_DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_class WHERE relname IN ('edr_tenants','edr_agents','edr_agent_certificates','edr_enrollment_audit') AND relkind='r'")"
if [[ "$existing" != "0" ]]; then
  echo "Refusing to run: EDR tables already exist; use an empty disposable database" >&2
  exit 2
fi

psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f backend/migrations/0001_agent_enrollment.up.sql

# All assertions run in a single rollback-only transaction. The schema remains
# for operator inspection; discard the entire test database after this run.
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
INSERT INTO edr_tenants(tenant_id, display_name) VALUES ('tenantA','Tenant A'),('tenantB','Tenant B');
INSERT INTO edr_agents(tenant_id,agent_id,platform) VALUES
  ('tenantA','win01','windows'),('tenantB','win01','linux');

INSERT INTO edr_agent_certificates(tenant_id,agent_id,fingerprint_sha256,not_before,not_after)
VALUES ('tenantA','win01',decode(repeat('ab',32),'hex'),now()-interval '1 hour',now()+interval '1 day');
INSERT INTO edr_enrollment_audit(tenant_id,agent_id,event_type,actor_id)
VALUES ('tenantA','win01','certificate_enrolled','migration-test');

DO $$
BEGIN
  IF (SELECT count(*) FROM edr_agent_certificates WHERE revoked_at IS NULL) != 1 THEN
    RAISE EXCEPTION 'expected exactly one active certificate';
  END IF;
  IF (SELECT count(*) FROM edr_agent_certificates WHERE tenant_id='tenantB') != 0 THEN
    RAISE EXCEPTION 'cross-tenant certificate leakage';
  END IF;
END $$;

-- PostgreSQL constraints are checked by catching expected errors in subtransactions.
DO $$
BEGIN
  BEGIN
    INSERT INTO edr_agent_certificates(tenant_id,agent_id,fingerprint_sha256,not_before,not_after)
    VALUES ('tenantA','win01',decode(repeat('cd',32),'hex'),now()-interval '1 hour',now()+interval '1 day');
    RAISE EXCEPTION 'duplicate active certificate unexpectedly accepted';
  EXCEPTION WHEN unique_violation THEN NULL;
  END;
  BEGIN
    INSERT INTO edr_agent_certificates(tenant_id,agent_id,fingerprint_sha256,not_before,not_after)
    VALUES ('tenantB','missing',decode(repeat('cd',32),'hex'),now()-interval '1 hour',now()+interval '1 day');
    RAISE EXCEPTION 'unknown agent unexpectedly accepted';
  EXCEPTION WHEN foreign_key_violation THEN NULL;
  END;
  BEGIN
    INSERT INTO edr_agent_certificates(tenant_id,agent_id,fingerprint_sha256,not_before,not_after)
    VALUES ('tenantB','win01',decode('abcd','hex'),now()-interval '1 hour',now()+interval '1 day');
    RAISE EXCEPTION 'short fingerprint unexpectedly accepted';
  EXCEPTION WHEN check_violation THEN NULL;
  END;
END $$;

-- Certificate rotation: revoke old leaf, then enroll new leaf atomically.
UPDATE edr_agent_certificates
SET revoked_at=now(),revoke_reason='rotation'
WHERE tenant_id='tenantA' AND agent_id='win01' AND revoked_at IS NULL;
INSERT INTO edr_agent_certificates(tenant_id,agent_id,fingerprint_sha256,not_before,not_after)
VALUES ('tenantA','win01',decode(repeat('cd',32),'hex'),now()-interval '1 hour',now()+interval '1 day');
DO $$
BEGIN
  IF (SELECT count(*) FROM edr_agent_certificates
      WHERE tenant_id='tenantA' AND agent_id='win01' AND revoked_at IS NULL) != 1 THEN
    RAISE EXCEPTION 'certificate rotation did not retain exactly one active leaf';
  END IF;
END $$;
ROLLBACK;
SQL
echo "PostgreSQL enrollment migration and constraint smoke test passed"
