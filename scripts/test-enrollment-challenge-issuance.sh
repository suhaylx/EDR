#!/usr/bin/env bash
# Disposable PostgreSQL 16 only. Uses a fresh empty database.
set -euo pipefail
: "${EDR_TEST_DATABASE_URL:?Use an empty disposable PostgreSQL database}"
command -v psql >/dev/null
existing="$(psql "$EDR_TEST_DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_class WHERE relname IN ('edr_tenants','edr_agents','edr_agent_certificates','edr_enrollment_challenges','edr_enrollment_challenge_audit') AND relkind='r'")"
if [[ "$existing" != "0" ]]; then
  echo "Refusing to run on nonempty EDR database" >&2
  exit 2
fi
for migration in \
  0001_agent_enrollment \
  0002_enrollment_audit_guard \
  0003_certificate_rotation \
  0004_enrollment_challenges \
  0005_scan_job_queue \
  0006_atomic_agent_enrollment \
  0007_enrollment_challenge_issuance; do
  psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f "backend/migrations/${migration}.up.sql"
done
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
INSERT INTO edr_tenants(tenant_id,display_name)
VALUES ('tenantA','A'),('tenantB','B'),('disabled','Disabled');
UPDATE edr_tenants SET disabled_at=now() WHERE tenant_id='disabled';
INSERT INTO edr_agents(tenant_id,agent_id,platform)
VALUES ('tenantA','existing','linux');
DO $issue$
DECLARE ok boolean;
BEGIN
  ok:=edr_issue_enrollment_challenge(
    '11111111-1111-4111-8111-111111111111','tenantA','win01',
    decode(repeat('aa',32),'hex'),300,'trusted-issuer');
  IF NOT ok THEN RAISE EXCEPTION 'valid challenge issuance rejected'; END IF;
  IF (SELECT count(*) FROM edr_enrollment_challenges
      WHERE tenant_id='tenantA' AND agent_id='win01' AND consumed_at IS NULL)<>1 THEN
    RAISE EXCEPTION 'issued challenge not persisted'; END IF;
  IF (SELECT count(*) FROM edr_enrollment_challenge_audit
      WHERE tenant_id='tenantA' AND agent_id='win01' AND event_type='challenge_issued')<>1 THEN
    RAISE EXCEPTION 'challenge issuance audit missing'; END IF;
  ok:=edr_issue_enrollment_challenge(
    '22222222-2222-4222-8222-222222222222','tenantA','win01',
    decode(repeat('bb',32),'hex'),300,'trusted-issuer');
  IF ok THEN RAISE EXCEPTION 'second live challenge issued to same agent'; END IF;
  ok:=edr_issue_enrollment_challenge(
    '33333333-3333-4333-8333-333333333333','disabled','win01',
    decode(repeat('cc',32),'hex'),300,'trusted-issuer');
  IF ok THEN RAISE EXCEPTION 'disabled tenant received challenge'; END IF;
  ok:=edr_issue_enrollment_challenge(
    '33333333-3333-4333-8333-333333333333','tenantA','existing',
    decode(repeat('cc',32),'hex'),300,'trusted-issuer');
  IF ok THEN RAISE EXCEPTION 'existing agent received fresh enrollment'; END IF;
  ok:=edr_issue_enrollment_challenge(
    '33333333-3333-4333-8333-333333333333','tenantA','newagent',
    decode(repeat('cc',32),'hex'),59,'trusted-issuer');
  IF ok THEN RAISE EXCEPTION 'short lifetime accepted'; END IF;
  ok:=edr_issue_enrollment_challenge(
    '33333333-3333-4333-8333-333333333333','tenantA','newagent',
    decode(repeat('cc',32),'hex'),601,'trusted-issuer');
  IF ok THEN RAISE EXCEPTION 'long lifetime accepted'; END IF;
  ok:=edr_issue_enrollment_challenge(
    '33333333-3333-4333-8333-333333333333','tenantA','newagent',
    decode(repeat('cc',32),'hex'),300,'');
  IF ok THEN RAISE EXCEPTION 'missing issuer actor accepted'; END IF;

  -- A consumed challenge cannot be replayed and may be followed by a
  -- new one only while no device has been enrolled.
  ok:=edr_consume_enrollment_challenge(
    '11111111-1111-4111-8111-111111111111','tenantA','win01',
    decode(repeat('aa',32),'hex'));
  IF NOT ok THEN RAISE EXCEPTION 'valid issued challenge did not consume'; END IF;
  ok:=edr_consume_enrollment_challenge(
    '11111111-1111-4111-8111-111111111111','tenantA','win01',
    decode(repeat('aa',32),'hex'));
  IF ok THEN RAISE EXCEPTION 'consumed challenge replay accepted'; END IF;
  ok:=edr_issue_enrollment_challenge(
    '22222222-2222-4222-8222-222222222222','tenantA','win01',
    decode(repeat('bb',32),'hex'),300,'trusted-issuer');
  IF NOT ok THEN RAISE EXCEPTION 'new challenge following consumption denied'; END IF;

  -- PostgreSQL index protects even if a privileged caller bypasses the
  -- function and attempts to insert directly.
  BEGIN
    INSERT INTO edr_enrollment_challenges(
      challenge_id,tenant_id,agent_id,challenge_digest,expires_at)
    VALUES ('99999999-9999-4999-8999-999999999999','tenantA','win01',
      decode(repeat('ee',32),'hex'),now()+interval '5 minutes');
    RAISE EXCEPTION 'duplicate pending challenge index bypassed';
  EXCEPTION WHEN unique_violation THEN NULL;
  END;

  -- Audit writes are append-only for the configured application role.
  BEGIN
    UPDATE edr_enrollment_challenge_audit SET actor_id='tampered';
    RAISE EXCEPTION 'challenge issuance audit tamper accepted';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
END $issue$;

-- Expired challenge is invalidated and recorded before renewal.
INSERT INTO edr_enrollment_challenges(
  challenge_id,tenant_id,agent_id,challenge_digest,created_at,expires_at)
VALUES ('44444444-4444-4444-8444-444444444444','tenantB','linux01',
  decode(repeat('dd',32),'hex'),now()-interval '10 minutes',now()-interval '1 second');
DO $renew$
DECLARE ok boolean;
BEGIN
  ok:=edr_issue_enrollment_challenge(
    '55555555-5555-4555-8555-555555555555','tenantB','linux01',
    decode(repeat('ff',32),'hex'),300,'trusted-issuer');
  IF NOT ok THEN RAISE EXCEPTION 'expired challenge was not renewed'; END IF;
  IF (SELECT consumed_at FROM edr_enrollment_challenges
      WHERE challenge_id='44444444-4444-4444-8444-444444444444') IS NULL THEN
    RAISE EXCEPTION 'expired challenge was not invalidated'; END IF;
  IF (SELECT count(*) FROM edr_enrollment_challenge_audit
      WHERE tenant_id='tenantB' AND agent_id='linux01' AND event_type='challenge_expired')<>1 THEN
    RAISE EXCEPTION 'expiration was not audited'; END IF;
END $renew$;
ROLLBACK;
SQL

# Two separate sessions: tenant disablement must commit before a concurrent
# challenge issue can complete. An unlocked tenant snapshot would allow a
# challenge for a tenant already disabled.
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
INSERT INTO edr_tenants(tenant_id,display_name) VALUES ('raceTenant','Race');
SQL
PGAPPNAME=edr-issuer-ci-disable psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL' >/dev/null 2>&1 &
BEGIN;
UPDATE edr_tenants SET disabled_at=clock_timestamp() WHERE tenant_id='raceTenant';
SELECT pg_sleep(3);
COMMIT;
SQL
disabler_pid=$!
ready=0
for _ in $(seq 1 60); do
  activity="$(psql "$EDR_TEST_DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_stat_activity WHERE application_name='edr-issuer-ci-disable' AND state='active' AND query LIKE '%pg_sleep(3)%'")"
  if [[ "$activity" == "1" ]]; then ready=1; break; fi
  sleep 0.1
done
if [[ "$ready" != "1" ]]; then
  wait "$disabler_pid" || true
  echo "Could not establish disablement/issuance race fixture" >&2
  exit 1
fi
issued="$(psql "$EDR_TEST_DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c "SET statement_timeout='10s'; SELECT edr_issue_enrollment_challenge('66666666-6666-4666-8666-666666666666','raceTenant','win01',decode(repeat('ab',32),'hex'),300,'race-issuer')")"
wait "$disabler_pid"
if [[ "$(printf '%s\n' "$issued" | tail -n 1)" != "f" ]]; then
  echo "Disabled tenant received a race-issued challenge" >&2
  exit 1
fi
count="$(psql "$EDR_TEST_DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM edr_enrollment_challenges WHERE tenant_id='raceTenant'")"
if [[ "$count" != "0" ]]; then
  echo "Denied challenge issuance mutated database" >&2
  exit 1
fi
echo "PostgreSQL challenge issuance + race protection passed"
