#!/usr/bin/env bash
# Disposable PostgreSQL only; requires a fresh database.
set -euo pipefail
: "${EDR_TEST_DATABASE_URL:?Set a disposable PostgreSQL connection URL}"
command -v psql >/dev/null
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f backend/migrations/0001_agent_enrollment.up.sql
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f backend/migrations/0004_enrollment_challenges.up.sql
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
INSERT INTO edr_tenants(tenant_id,display_name) VALUES ('tenantA','A'),('tenantB','B'),('disabled','D');
UPDATE edr_tenants SET disabled_at=now() WHERE tenant_id='disabled';
INSERT INTO edr_enrollment_challenges(challenge_id,tenant_id,agent_id,challenge_digest,created_at,expires_at)
VALUES
('11111111-1111-4111-8111-111111111111','tenantA','win01',decode(repeat('aa',32),'hex'),now(),now()+interval '10 minutes'),
('22222222-2222-4222-8222-222222222222','tenantA','win01',decode(repeat('bb',32),'hex'),now()-interval '2 minutes',now()-interval '1 second'),
('33333333-3333-4333-8333-333333333333','disabled','win01',decode(repeat('cc',32),'hex'),now(),now()+interval '10 minutes');
DO $$
DECLARE ok boolean;
BEGIN
  ok := edr_consume_enrollment_challenge('11111111-1111-4111-8111-111111111111','tenantB','win01',decode(repeat('aa',32),'hex'));
  IF ok THEN RAISE EXCEPTION 'cross-tenant claim accepted'; END IF;
  ok := edr_consume_enrollment_challenge('11111111-1111-4111-8111-111111111111','tenantA','other',decode(repeat('aa',32),'hex'));
  IF ok THEN RAISE EXCEPTION 'wrong device accepted'; END IF;
  ok := edr_consume_enrollment_challenge('11111111-1111-4111-8111-111111111111','tenantA','win01',decode(repeat('ff',32),'hex'));
  IF ok THEN RAISE EXCEPTION 'wrong digest accepted'; END IF;
  ok := edr_consume_enrollment_challenge('22222222-2222-4222-8222-222222222222','tenantA','win01',decode(repeat('bb',32),'hex'));
  IF ok THEN RAISE EXCEPTION 'expired challenge accepted'; END IF;
  ok := edr_consume_enrollment_challenge('33333333-3333-4333-8333-333333333333','disabled','win01',decode(repeat('cc',32),'hex'));
  IF ok THEN RAISE EXCEPTION 'disabled tenant accepted'; END IF;
  ok := edr_consume_enrollment_challenge('11111111-1111-4111-8111-111111111111','tenantA','win01',decode(repeat('aa',32),'hex'));
  IF NOT ok THEN RAISE EXCEPTION 'valid challenge rejected'; END IF;
  ok := edr_consume_enrollment_challenge('11111111-1111-4111-8111-111111111111','tenantA','win01',decode(repeat('aa',32),'hex'));
  IF ok THEN RAISE EXCEPTION 'replayed challenge accepted'; END IF;
  IF (SELECT count(*) FROM edr_enrollment_challenges WHERE consumed_at IS NOT NULL) <> 1 THEN
    RAISE EXCEPTION 'wrong consumed challenge count';
  END IF;
END $$;
ROLLBACK;
SQL
echo "Enrollment challenge single-use integration passed"
