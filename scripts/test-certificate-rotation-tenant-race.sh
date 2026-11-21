#!/usr/bin/env bash
# P0 QA: rotation must serialize with concurrent tenant disablement.
# Empty disposable PostgreSQL CI database only; 0001-0003 applied.
set -euo pipefail
: "$EDR_TEST_DATABASE_URL"
[[ "$EDR_QA_DISPOSABLE_DB" == "yes" ]] || { echo "Disposable DB only" >&2; exit 2; }
command -v psql >/dev/null
command -v timeout >/dev/null
tmp="$(mktemp -d)"
export QA_ROTATE_READY="$tmp/ready"
export QA_ROTATE_FIFO="$tmp/release"
mkfifo "$QA_ROTATE_FIFO"
admin=''
worker=''
cleanup() {
  rc=$?
  trap - EXIT
  for pid in "$admin" "$worker"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  if (( rc != 0 )); then
    cat "$tmp/admin.log" >&2 2>/dev/null || true
    cat "$tmp/worker.log" >&2 2>/dev/null || true
  fi
  psql "$EDR_TEST_DATABASE_URL" -X -q -v ON_ERROR_STOP=1 <<'SQL' >/dev/null || true
BEGIN;
DELETE FROM edr_enrollment_audit WHERE tenant_id='qa-rotate-race';
DELETE FROM edr_agent_certificates WHERE tenant_id='qa-rotate-race';
DELETE FROM edr_agents WHERE tenant_id='qa-rotate-race';
DELETE FROM edr_tenants WHERE tenant_id='qa-rotate-race';
COMMIT;
SQL
  rm -rf "$tmp"
  exit "$rc"
}
trap cleanup EXIT

psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
INSERT INTO edr_tenants(tenant_id,display_name)
VALUES ('qa-rotate-race','QA rotation vs tenant disable');
INSERT INTO edr_agents(tenant_id,agent_id,platform)
VALUES ('qa-rotate-race','agent01','linux');
INSERT INTO edr_agent_certificates
  (tenant_id,agent_id,fingerprint_sha256,not_before,not_after)
VALUES ('qa-rotate-race','agent01',decode(repeat('aa',32),'hex'),
  now()-interval '5 minutes',now()+interval '1 day');
COMMIT;
SQL

# Admin holds a tenant UPDATE without committing.
PGAPPNAME=qa_rotation_admin timeout 35 psql "$EDR_TEST_DATABASE_URL" \
  -X -v ON_ERROR_STOP=1 >"$tmp/admin.log" 2>&1 <<'SQL' &
BEGIN;
UPDATE edr_tenants SET disabled_at=clock_timestamp()
WHERE tenant_id='qa-rotate-race';
\! touch "$QA_ROTATE_READY"
\! timeout 28 sh -c 'IFS= read -r ack < "$QA_ROTATE_FIFO"'
COMMIT;
SQL
admin=$!

ready=0
for ((i=0;i<100;i++)); do
  if [[ -f "$QA_ROTATE_READY" ]]; then ready=1; break; fi
  if ! kill -0 "$admin" 2>/dev/null; then break; fi
  sleep 0.1
done
[[ "$ready" == "1" ]] || { echo "Admin transaction not holding tenant row" >&2; exit 1; }

PGAPPNAME=qa_rotation_worker timeout 30 psql "$EDR_TEST_DATABASE_URL" \
  -X -v ON_ERROR_STOP=1 >"$tmp/worker.log" 2>&1 <<'SQL' &
DO $race$
BEGIN
  IF edr_rotate_agent_certificate('qa-rotate-race','agent01',
    decode(repeat('aa',32),'hex'),decode(repeat('bb',32),'hex'),
    now()-interval '1 minute',now()+interval '1 day','qa-operator') THEN
    RAISE EXCEPTION 'cert rotated while tenant disable was committing';
  END IF;
END $race$;
SQL
worker=$!

# Require a positive Postgres lock-wait observation, not an arbitrary delay.
blocked=0
for ((i=0;i<100;i++)); do
  count="$(psql "$EDR_TEST_DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c \
    "SELECT count(*) FROM pg_stat_activity
      WHERE application_name='qa_rotation_worker' AND wait_event_type='Lock'")"
  if [[ "$count" == "1" ]]; then blocked=1; break; fi
  if ! kill -0 "$worker" 2>/dev/null; then break; fi
  sleep 0.1
done
[[ "$blocked" == "1" ]] || { echo "Rotation did not wait on tenant update" >&2; exit 1; }

printf 'release\n' | timeout 5 tee "$QA_ROTATE_FIFO" >/dev/null
wait "$admin"
admin=''
wait "$worker"
worker=''

psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
DO $verify$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM edr_tenants WHERE
    tenant_id='qa-rotate-race' AND disabled_at IS NOT NULL) THEN
    RAISE EXCEPTION 'tenant disable was not committed'; END IF;
  IF NOT EXISTS (SELECT 1 FROM edr_agent_certificates WHERE
    tenant_id='qa-rotate-race' AND agent_id='agent01'
    AND fingerprint_sha256=decode(repeat('aa',32),'hex')
    AND revoked_at IS NULL) THEN
    RAISE EXCEPTION 'denied rotation modified valid old certificate'; END IF;
  IF EXISTS (SELECT 1 FROM edr_agent_certificates WHERE
    tenant_id='qa-rotate-race' AND agent_id='agent01'
    AND fingerprint_sha256=decode(repeat('bb',32),'hex')) THEN
    RAISE EXCEPTION 'denied rotation enrolled unauthorized certificate'; END IF;
  IF EXISTS (SELECT 1 FROM edr_enrollment_audit WHERE
    tenant_id='qa-rotate-race') THEN
    RAISE EXCEPTION 'denied rotation wrote success audit'; END IF;
  IF edr_rotate_agent_certificate('qa-rotate-race','agent01',
    decode(repeat('aa',32),'hex'),decode(repeat('cc',32),'hex'),
    now()-interval '1 minute',now()+interval '1 day','qa-operator') THEN
    RAISE EXCEPTION 'committed disabled tenant rotated certificate'; END IF;
END $verify$;
SQL
echo "Tenant disable serialized before certificate rotation; no mutation"
