#!/usr/bin/env bash
# P0 QA: in-flight scan completion must serialize with admin revocation.
# Requires empty disposable CI schema initialized by test-scan-job-queue.sh.
set -euo pipefail
: "${EDR_TEST_DATABASE_URL:?Set disposable PostgreSQL URL}"
[[ "${EDR_QA_DISPOSABLE_DB:-}" == "yes" ]] || { echo 'Disposable DB flag required' >&2; exit 2; }
command -v psql >/dev/null
command -v timeout >/dev/null
tmp="$(mktemp -d)"
export QA_COMPLETE_READY="$tmp/ready"
export QA_COMPLETE_RELEASE="$tmp/release"
mkfifo "$QA_COMPLETE_RELEASE"
holder=''
completer1=''
completer2=''
cleanup() {
  rc=$?
  trap - EXIT
  for pid in "$holder" "$completer1" "$completer2"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  if (( rc != 0 )); then
    for name in holder completion-agent completion-tenant; do
      echo "QA completion output: $name" >&2
      cat "$tmp/$name.log" >&2 2>/dev/null || true
    done
  fi
  psql "$EDR_TEST_DATABASE_URL" -X -q -v ON_ERROR_STOP=1 >/dev/null <<'SQL' || true
BEGIN;
DELETE FROM edr_scan_jobs WHERE tenant_id IN ('qa-complete-agent','qa-complete-tenant');
DELETE FROM edr_agents WHERE tenant_id IN ('qa-complete-agent','qa-complete-tenant');
DELETE FROM edr_tenants WHERE tenant_id IN ('qa-complete-agent','qa-complete-tenant');
COMMIT;
SQL
  rm -rf "$tmp"
  exit "$rc"
}
trap cleanup EXIT

# Commit two valid leases before the administrator starts revoking access.
psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
BEGIN;
INSERT INTO edr_tenants(tenant_id,display_name)
VALUES ('qa-complete-agent','QA completion agent race'),
       ('qa-complete-tenant','QA completion tenant race');
INSERT INTO edr_agents(tenant_id,agent_id,platform)
VALUES ('qa-complete-agent','linux01','linux'),
       ('qa-complete-tenant','win01','windows');
INSERT INTO edr_scan_jobs(job_id,tenant_id,agent_id,scan_root)
VALUES ('c1111111-1111-4111-8111-111111111111','qa-complete-agent','linux01','/qa'),
       ('c2222222-2222-4222-8222-222222222222','qa-complete-tenant','win01','C:/QA');
DO $lease$
DECLARE a record; b record;
BEGIN
 SELECT * INTO a FROM edr_claim_scan_job('qa-complete-agent','linux01','test',
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',300);
 SELECT * INTO b FROM edr_claim_scan_job('qa-complete-tenant','win01','test',
    'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',300);
 IF a.job_id IS DISTINCT FROM 'c1111111-1111-4111-8111-111111111111'::uuid
    OR b.job_id IS DISTINCT FROM 'c2222222-2222-4222-8222-222222222222'::uuid
 THEN RAISE EXCEPTION 'completion race leases not created'; END IF;
END $lease$;
COMMIT;
SQL

PGAPPNAME=qa_complete_revoke_holder timeout 35 psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 >"$tmp/holder.log" 2>&1 <<'SQL' &
BEGIN;
UPDATE edr_agents SET revoked_at=clock_timestamp()
WHERE tenant_id='qa-complete-agent' AND agent_id='linux01';
UPDATE edr_tenants SET disabled_at=clock_timestamp()
WHERE tenant_id='qa-complete-tenant';
\! touch "$QA_COMPLETE_READY"
\! timeout 28 sh -c 'IFS= read -r response < "$QA_COMPLETE_RELEASE"'
COMMIT;
SQL
holder=$!

ready=0
for (( i=0; i<100; i++ )); do
  if [[ -f "$QA_COMPLETE_READY" ]]; then ready=1; break; fi
  if ! kill -0 "$holder" 2>/dev/null; then exit 1; fi
  sleep 0.1
done
[[ "$ready" == "1" ]] || { echo 'Revocation holder not ready' >&2; exit 1; }

PGAPPNAME=qa_completion_locked_agent timeout 30 psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 >"$tmp/completion-agent.log" 2>&1 <<'SQL' &
DO $complete$
BEGIN
 IF edr_complete_scan_job('qa-complete-agent','linux01',
   'c1111111-1111-4111-8111-111111111111',
   'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',true) THEN
   RAISE EXCEPTION 'revoked agent completed successful scan'; END IF;
END $complete$;
SQL
completer1=$!

PGAPPNAME=qa_completion_locked_tenant timeout 30 psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 >"$tmp/completion-tenant.log" 2>&1 <<'SQL' &
DO $complete$
BEGIN
 IF edr_complete_scan_job('qa-complete-tenant','win01',
   'c2222222-2222-4222-8222-222222222222',
   'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',false) THEN
   RAISE EXCEPTION 'disabled tenant completed failed scan'; END IF;
END $complete$;
SQL
completer2=$!

# Explicitly observe two lock waits while admin changes are uncommitted.
blocked=0
for (( i=0; i<100; i++ )); do
  n="$(psql "$EDR_TEST_DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c \
    "SELECT count(DISTINCT application_name) FROM pg_stat_activity
     WHERE application_name IN ('qa_completion_locked_agent','qa_completion_locked_tenant')
       AND wait_event_type='Lock'")"
  if [[ "$n" == "2" ]]; then blocked=1; break; fi
  if ! kill -0 "$completer1" 2>/dev/null || ! kill -0 "$completer2" 2>/dev/null; then break; fi
  sleep 0.1
done
[[ "$blocked" == "1" ]] || { echo 'Completion bypassed principal transaction lock' >&2; exit 1; }

printf 'release\n' | timeout 5 tee "$QA_COMPLETE_RELEASE" >/dev/null
wait "$holder"
holder=''
wait "$completer1"
completer1=''
wait "$completer2"
completer2=''

psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 <<'SQL'
DO $verify$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM edr_scan_jobs WHERE
    job_id='c1111111-1111-4111-8111-111111111111'
    AND state='leased' AND attempt_count=1
    AND lease_token='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa') THEN
   RAISE EXCEPTION 'revoked-agent denial mutated scan lease'; END IF;
 IF NOT EXISTS(SELECT 1 FROM edr_scan_jobs WHERE
    job_id='c2222222-2222-4222-8222-222222222222'
    AND state='leased' AND attempt_count=1
    AND lease_token='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb') THEN
   RAISE EXCEPTION 'disabled-tenant denial mutated scan lease'; END IF;
 IF edr_complete_scan_job('qa-complete-agent','linux01',
    'c1111111-1111-4111-8111-111111111111',
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',false) THEN
   RAISE EXCEPTION 'revoked agent completed after commit'; END IF;
 IF edr_complete_scan_job('qa-complete-tenant','win01',
    'c2222222-2222-4222-8222-222222222222',
    'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',true) THEN
   RAISE EXCEPTION 'disabled tenant completed after commit'; END IF;
END $verify$;
SQL

echo 'Concurrent agent revocation and tenant disablement serialized before completion'
