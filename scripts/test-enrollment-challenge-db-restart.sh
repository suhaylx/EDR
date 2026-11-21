#!/usr/bin/env bash
# Day 2 P0 QA: single-use enrollment challenge state survives ACTUAL restart
# of GitHub Actions' disposable PostgreSQL service, never a real host.
# Usage: test-enrollment-challenge-db-restart.sh seed|verify
set -euo pipefail
: "${EDR_TEST_DATABASE_URL:?Set disposable PostgreSQL URL}"
[[ "${EDR_QA_DISPOSABLE_DB:-}" == "yes" ]] || {
  echo 'Refusing non-disposable database: set EDR_QA_DISPOSABLE_DB=yes' >&2
  exit 2
}
command -v psql >/dev/null
case "${1:-}" in
seed)
  psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
INSERT INTO edr_tenants(tenant_id,display_name)
VALUES ('qa-enroll-restart-a','QA restart A'),
       ('qa-enroll-restart-b','QA restart B'),
       ('qa-enroll-restart-disabled','QA restart disabled');
UPDATE edr_tenants SET disabled_at=transaction_timestamp()
  WHERE tenant_id='qa-enroll-restart-disabled';
INSERT INTO edr_enrollment_challenges(
  challenge_id,tenant_id,agent_id,challenge_digest,created_at,expires_at
) VALUES
('d1111111-1111-4111-8111-111111111111','qa-enroll-restart-a','win01',
  decode(repeat('aa',32),'hex'),now()-interval '1 minute',now()+interval '30 minutes'),
('d2222222-2222-4222-8222-222222222222','qa-enroll-restart-a','linux01',
  decode(repeat('bb',32),'hex'),now()-interval '1 minute',now()+interval '30 minutes'),
('d3333333-3333-4333-8333-333333333333','qa-enroll-restart-disabled','win01',
  decode(repeat('cc',32),'hex'),now()-interval '1 minute',now()+interval '30 minutes'),
('d4444444-4444-4444-8444-444444444444','qa-enroll-restart-b','linux02',
  decode(repeat('dd',32),'hex'),now()-interval '30 minutes',now()-interval '1 minute');
DO $seed$
BEGIN
  IF NOT edr_consume_enrollment_challenge(
    'd1111111-1111-4111-8111-111111111111',
    'qa-enroll-restart-a','win01',decode(repeat('aa',32),'hex')) THEN
    RAISE EXCEPTION 'could not consume initial enrolled challenge'; END IF;
  IF (SELECT consumed_at FROM edr_enrollment_challenges
      WHERE challenge_id='d1111111-1111-4111-8111-111111111111') IS NULL THEN
    RAISE EXCEPTION 'single-use challenge consumption not persisted before restart'; END IF;
END $seed$;
COMMIT;
SQL
  echo 'Committed one consumed and three unconsumed enrollment challenges before PostgreSQL restart'
  ;;
verify)
  psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
DO $verify$
BEGIN
  IF (SELECT count(*) FROM edr_enrollment_challenges WHERE
      tenant_id LIKE 'qa-enroll-restart-%') <> 4 THEN
    RAISE EXCEPTION 'challenge rows were lost across PostgreSQL restart'; END IF;
  IF NOT EXISTS(
    SELECT 1 FROM edr_enrollment_challenges
    WHERE challenge_id='d1111111-1111-4111-8111-111111111111'
      AND consumed_at IS NOT NULL) THEN
    RAISE EXCEPTION 'consumption watermark lost across PostgreSQL restart'; END IF;
  IF edr_consume_enrollment_challenge('d1111111-1111-4111-8111-111111111111',
     'qa-enroll-restart-a','win01',decode(repeat('aa',32),'hex')) THEN
    RAISE EXCEPTION 'consumed enrollment challenge replay accepted after restart'; END IF;
  IF edr_consume_enrollment_challenge('d2222222-2222-4222-8222-222222222222',
     'qa-enroll-restart-b','linux01',decode(repeat('bb',32),'hex')) THEN
    RAISE EXCEPTION 'wrong tenant accepted after restart'; END IF;
  IF edr_consume_enrollment_challenge('d2222222-2222-4222-8222-222222222222',
     'qa-enroll-restart-a','win01',decode(repeat('bb',32),'hex')) THEN
    RAISE EXCEPTION 'wrong device accepted after restart'; END IF;
  IF edr_consume_enrollment_challenge('d2222222-2222-4222-8222-222222222222',
     'qa-enroll-restart-a','linux01',decode(repeat('ee',32),'hex')) THEN
    RAISE EXCEPTION 'wrong digest accepted after restart'; END IF;
  IF edr_consume_enrollment_challenge('d3333333-3333-4333-8333-333333333333',
     'qa-enroll-restart-disabled','win01',decode(repeat('cc',32),'hex')) THEN
    RAISE EXCEPTION 'disabled tenant consumed challenge after restart'; END IF;
  IF edr_consume_enrollment_challenge('d4444444-4444-4444-8444-444444444444',
     'qa-enroll-restart-b','linux02',decode(repeat('dd',32),'hex')) THEN
    RAISE EXCEPTION 'expired challenge consumed after restart'; END IF;
  IF NOT edr_consume_enrollment_challenge('d2222222-2222-4222-8222-222222222222',
     'qa-enroll-restart-a','linux01',decode(repeat('bb',32),'hex')) THEN
    RAISE EXCEPTION 'unconsumed valid challenge became unusable after restart'; END IF;
  IF edr_consume_enrollment_challenge('d2222222-2222-4222-8222-222222222222',
     'qa-enroll-restart-a','linux01',decode(repeat('bb',32),'hex')) THEN
    RAISE EXCEPTION 'fresh challenge replay accepted in same post-restart session'; END IF;
  IF (SELECT count(*) FROM edr_enrollment_challenges WHERE
       tenant_id LIKE 'qa-enroll-restart-%' AND consumed_at IS NOT NULL) <> 2 THEN
    RAISE EXCEPTION 'wrong number of consumed challenges after restart'; END IF;
END $verify$;
DELETE FROM edr_enrollment_challenges WHERE tenant_id LIKE 'qa-enroll-restart-%';
DELETE FROM edr_tenants WHERE tenant_id LIKE 'qa-enroll-restart-%';
COMMIT;
SQL
  echo 'Actual PostgreSQL service restart: challenge consumption, expiry and tenant isolation persisted'
  ;;
*)
  echo "Usage: $0 seed|verify" >&2
  exit 2
  ;;
esac
