#!/usr/bin/env bash
# Disposable PostgreSQL only. Requires a fresh database.
set -euo pipefail
: "${EDR_TEST_DATABASE_URL:?Set EDR_TEST_DATABASE_URL to a disposable PostgreSQL database}"
command -v psql >/dev/null
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f backend/migrations/0001_agent_enrollment.up.sql
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f backend/migrations/0002_enrollment_audit_guard.up.sql
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
INSERT INTO edr_tenants(tenant_id,display_name) VALUES ('tenantA','A'),('tenantB','B');
INSERT INTO edr_agents(tenant_id,agent_id,platform) VALUES ('tenantA','win01','windows'),('tenantB','win01','linux');
INSERT INTO edr_agent_certificates(tenant_id,agent_id,fingerprint_sha256,not_before,not_after)
VALUES ('tenantA','win01',decode(repeat('ab',32),'hex'),now()-interval '1 hour',now()+interval '1 day');

DO $$
DECLARE
    ok boolean;
BEGIN
    ok := edr_revoke_agent_certificate('tenantB','win01',decode(repeat('ab',32),'hex'),'soc-admin','rotation');
    IF ok THEN RAISE EXCEPTION 'cross-tenant revocation succeeded'; END IF;
    ok := edr_revoke_agent_certificate('tenantA','win01',decode(repeat('ab',32),'hex'),'soc-admin','rotation');
    IF NOT ok THEN RAISE EXCEPTION 'expected revocation'; END IF;
    ok := edr_revoke_agent_certificate('tenantA','win01',decode(repeat('ab',32),'hex'),'soc-admin','rotation');
    IF ok THEN RAISE EXCEPTION 'replayed revocation succeeded'; END IF;
    IF (SELECT count(*) FROM edr_enrollment_audit WHERE event_type='certificate_revoked') <> 1 THEN
        RAISE EXCEPTION 'missing or duplicated audit';
    END IF;
    BEGIN
        UPDATE edr_enrollment_audit SET actor_id='tampered';
        RAISE EXCEPTION 'audit mutation unexpectedly succeeded';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    BEGIN
        DELETE FROM edr_enrollment_audit;
        RAISE EXCEPTION 'audit deletion unexpectedly succeeded';
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
    BEGIN
        UPDATE edr_agent_certificates SET revoked_at=NULL
        WHERE tenant_id='tenantA' AND agent_id='win01';
        RAISE EXCEPTION 'certificate reactivation unexpectedly succeeded';
    EXCEPTION WHEN check_violation THEN NULL;
    END;
    BEGIN
        PERFORM edr_revoke_agent_certificate('tenantA','win01',decode(repeat('ab',32),'hex'),'','bad');
        RAISE EXCEPTION 'empty actor unexpectedly accepted';
    EXCEPTION WHEN invalid_parameter_value THEN NULL;
    END;
END $$;
ROLLBACK;
SQL
echo "PostgreSQL revocation and append-only audit tests passed"
