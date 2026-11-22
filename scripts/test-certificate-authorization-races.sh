#!/usr/bin/env bash
# Called by test-runtime-privileges.sh inside its disposable DB/login fixture.
# Every schedule requires an observed PostgreSQL lock wait and a FIFO release.
set +x
set -euo pipefail
for required in EDR_TEST_DATABASE_URL EDR_TEST_RUNTIME_CONNECTION EDR_GRANT_TEST_PASSWORD; do
  if ! [[ -v "$required" ]]; then
    echo 'Missing isolated certificate-authorization race fixture configuration' >&2
    exit 2
  fi
done
command -v psql >/dev/null
command -v timeout >/dev/null
work="$(mktemp -d)"
first_pid=''
second_pid=''
cleanup_races() {
  result=$?
  trap - EXIT
  for worker_pid in "$first_pid" "$second_pid"; do
    if [[ -n "$worker_pid" ]] && kill -0 "$worker_pid" 2>/dev/null; then
      kill "$worker_pid" 2>/dev/null || true
      wait "$worker_pid" 2>/dev/null || true
    fi
  done
  if (( result != 0 )); then
    # These files contain only synthetic SQL fixture data, never DSNs/passwords.
    for race_log in "$work"/*.log; do
      [[ -f "$race_log" ]] && cat "$race_log" >&2
    done
  fi
  rm -rf "$work"
  exit "$result"
}
trap cleanup_races EXIT

cat > "$work/admin.sql" <<'SQL'
\set ON_ERROR_STOP on
BEGIN;
SELECT set_config('application_name', :'app_name', false) AS app_name \gset
SELECT :'operation'='revoke' AS revoke_case,
       :'operation'='rotate' AS rotate_case,
       :'operation'='operator_role' AS operator_case \gset
\if :revoke_case
  SELECT public.edr_revoke_agent_certificate(:'tenant','linux01',
    decode(repeat('aa',32),'hex'),'race-fixture','race-fixture') AS changed \gset
\elif :rotate_case
  SELECT public.edr_rotate_agent_certificate(:'tenant','linux01',
    decode(repeat('aa',32),'hex'),decode(repeat('bb',32),'hex'),
    clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 day','race-fixture') AS changed \gset
\elif :operator_case
  WITH changed_row AS (
    UPDATE public.edr_soc_operators SET role='viewer'
    WHERE tenant_id=:'tenant' AND operator_id='scanner' RETURNING operator_id
  ) SELECT count(*)=1 AS changed FROM changed_row \gset
\else
  -- An unchanged locked tuple is deliberate: it catches validity checks that
  -- used a transaction-start timestamp or evaluated expiry before the wait.
  SELECT count(*)=1 AS changed FROM (
    SELECT 1 FROM public.edr_agent_certificates
    WHERE tenant_id=:'tenant' AND agent_id='linux01'
      AND fingerprint_sha256=decode(repeat('aa',32),'hex')
    FOR UPDATE
  ) locked \gset
\endif
\if :changed
\else
  \echo 'FAIL: administrative race fixture did not find its row'
  \quit 3
\endif
\if :hold_admin
  \! touch "$EDR_AUTH_RACE_READY"
  \! timeout 20 sh -c 'IFS= read -r release < "$EDR_AUTH_RACE_FIFO"'
  \if :SHELL_ERROR
    \echo 'FAIL: administrative race release timed out'
    \quit 3
  \endif
\endif
COMMIT;
SQL

cat > "$work/runtime.sql" <<'SQL'
\set ON_ERROR_STOP on
BEGIN;
SELECT set_config('application_name', :'app_name', false) AS app_name \gset
SELECT :'operation'='operator_role' AS operator_case \gset
\if :operator_case
  SELECT public.edr_authorize_operator_certificate(:'tenant','scanner',
    decode(repeat('a1',32),'hex'),'scanner') AS authorized \gset
\else
  SELECT public.edr_authorize_agent_certificate(:'tenant','linux01',
    decode(repeat('aa',32),'hex')) AS authorized \gset
\endif
\if :expect_authorized
  \if :authorized
  \else
    \echo 'FAIL: first transaction did not acquire certificate authorization'
    \quit 3
  \endif
  \! touch "$EDR_AUTH_RACE_READY"
  \! timeout 20 sh -c 'IFS= read -r release < "$EDR_AUTH_RACE_FIFO"'
  \if :SHELL_ERROR
    \echo 'FAIL: runtime race release timed out'
    \quit 3
  \endif
  \if :operator_case
    SELECT count(*)=1 AS mutated FROM public.edr_enqueue_operator_scan_job(
      :'tenant','scanner','linux01',gen_random_uuid(),'race-request','/tmp/synthetic') \gset
  \else
    SELECT public.edr_record_agent_heartbeat(
      :'tenant','linux01','linux','race-test','','',false) AS mutated \gset
  \endif
  \if :mutated
  \else
    \echo 'FAIL: authorized transaction could not complete its mutation'
    \quit 3
  \endif
\else
  \if :authorized
    \echo 'FAIL: stale certificate/role authorized after administrative change or expiry'
    \quit 3
  \endif
  -- A rejected authorization must not dispatch any operational mutation.
\endif
COMMIT;
SQL

wait_ready() {
  local ready_file="$1"
  local worker_pid="$2"
  for ((probe=0;probe<150;probe++)); do
    [[ -f "$ready_file" ]] && return 0
    kill -0 "$worker_pid" 2>/dev/null || break
    sleep 0.05
  done
  echo 'FAIL: first transaction did not reach the coordinated hold point' >&2
  return 1
}

wait_lock() {
  local application="$1"
  local worker_pid="$2"
  local blocked
  for ((probe=0;probe<150;probe++)); do
    blocked="$(psql "$EDR_TEST_DATABASE_URL" -X -qAt -v ON_ERROR_STOP=1 \
      -v app_name="$application" <<'SQL'
SELECT count(*) FROM pg_stat_activity
WHERE datname=current_database() AND application_name=:'app_name'
  AND wait_event_type='Lock';
SQL
)"
    [[ "$blocked" == "1" ]] && return 0
    kill -0 "$worker_pid" 2>/dev/null || break
    sleep 0.05
  done
  echo 'FAIL: conflicting operation never entered an observable PostgreSQL lock wait' >&2
  return 1
}

release_fifo() {
  printf 'release\n' | timeout 5 tee "$1" >/dev/null
}

for operation in revoke rotate operator_role expiry; do
  for schedule in auth_first admin_first; do
    [[ "$operation" == expiry && "$schedule" == auth_first ]] && continue
    tenant="auth_$operation"_"$schedule"
    app_runtime="edr_race_runtime_$operation"_"$schedule"
    app_admin="edr_race_admin_$operation"_"$schedule"
    ready="$work/$tenant.ready"
    fifo="$work/$tenant.fifo"
    mkfifo "$fifo"
    psql "$EDR_TEST_DATABASE_URL" -X -q -v ON_ERROR_STOP=1 \
      -v tenant="$tenant" -v operation="$operation" <<'SQL'
BEGIN;
INSERT INTO public.edr_tenants(tenant_id,display_name)
VALUES (:'tenant','Certificate authorization race fixture');
INSERT INTO public.edr_agents(tenant_id,agent_id,platform)
VALUES (:'tenant','linux01','linux');
INSERT INTO public.edr_agent_certificates(tenant_id,agent_id,fingerprint_sha256,not_before,not_after)
VALUES (:'tenant','linux01',decode(repeat('aa',32),'hex'),clock_timestamp()-interval '1 minute',
  clock_timestamp()+CASE WHEN :'operation'='expiry' THEN interval '3 seconds' ELSE interval '1 day' END);
INSERT INTO public.edr_soc_operators(tenant_id,operator_id,fingerprint_sha256,role)
VALUES (:'tenant','scanner',decode(repeat('a1',32),'hex'),'scanner');
COMMIT;
SQL

    if [[ "$schedule" == auth_first ]]; then
      EDR_AUTH_RACE_READY="$ready" EDR_AUTH_RACE_FIFO="$fifo" \
        PGPASSWORD="$EDR_GRANT_TEST_PASSWORD" timeout 30 \
        psql "$EDR_TEST_RUNTIME_CONNECTION" -X -q -v ON_ERROR_STOP=1 \
        -v tenant="$tenant" -v operation="$operation" -v expect_authorized=true \
        -v app_name="$app_runtime" -f "$work/runtime.sql" \
        > "$work/$tenant.runtime.log" 2>&1 &
      first_pid=$!
      wait_ready "$ready" "$first_pid"

      timeout 30 psql "$EDR_TEST_DATABASE_URL" -X -q -v ON_ERROR_STOP=1 \
        -v tenant="$tenant" -v operation="$operation" -v hold_admin=false \
        -v app_name="$app_admin" -f "$work/admin.sql" \
        > "$work/$tenant.admin.log" 2>&1 &
      second_pid=$!
      wait_lock "$app_admin" "$second_pid"
    else
      EDR_AUTH_RACE_READY="$ready" EDR_AUTH_RACE_FIFO="$fifo" \
        timeout 30 psql "$EDR_TEST_DATABASE_URL" -X -q -v ON_ERROR_STOP=1 \
        -v tenant="$tenant" -v operation="$operation" -v hold_admin=true \
        -v app_name="$app_admin" -f "$work/admin.sql" \
        > "$work/$tenant.admin.log" 2>&1 &
      first_pid=$!
      wait_ready "$ready" "$first_pid"

      PGPASSWORD="$EDR_GRANT_TEST_PASSWORD" timeout 30 \
        psql "$EDR_TEST_RUNTIME_CONNECTION" -X -q -v ON_ERROR_STOP=1 \
        -v tenant="$tenant" -v operation="$operation" -v expect_authorized=false \
        -v app_name="$app_runtime" -f "$work/runtime.sql" \
        > "$work/$tenant.runtime.log" 2>&1 &
      second_pid=$!
      wait_lock "$app_runtime" "$second_pid"

      if [[ "$operation" == expiry ]]; then
        before_expiry="$(psql "$EDR_TEST_DATABASE_URL" -X -qAt -v ON_ERROR_STOP=1 \
          -v tenant="$tenant" -v app_name="$app_runtime" <<'SQL'
SELECT s.xact_start<c.not_after FROM pg_stat_activity s
JOIN public.edr_agent_certificates c ON c.tenant_id=:'tenant' AND c.agent_id='linux01'
WHERE s.application_name=:'app_name' AND s.datname=current_database() AND s.wait_event_type='Lock';
SQL
)"
        [[ "$before_expiry" == "t" ]] || { echo 'FAIL: expiry case did not begin before certificate expiration' >&2; exit 1; }
        expired=false
        for ((probe=0;probe<150;probe++)); do
          observed="$(psql "$EDR_TEST_DATABASE_URL" -X -qAt -v ON_ERROR_STOP=1 -v tenant="$tenant" <<'SQL'
SELECT clock_timestamp()>=not_after FROM public.edr_agent_certificates
WHERE tenant_id=:'tenant' AND agent_id='linux01';
SQL
)"
          if [[ "$observed" == "t" ]]; then expired=true; break; fi
          sleep 0.05
        done
        [[ "$expired" == true ]] || { echo 'FAIL: certificate expiry was not observed while authorization waited' >&2; exit 1; }
      fi
    fi

    release_fifo "$fifo"
    wait "$first_pid"
    first_pid=''
    wait "$second_pid"
    second_pid=''

    psql "$EDR_TEST_DATABASE_URL" -X -q -v ON_ERROR_STOP=1 \
      -v tenant="$tenant" -v operation="$operation" -v schedule="$schedule" <<'SQL'
SELECT set_config('edr.race_tenant', :'tenant', false) AS race_tenant \gset
SELECT set_config('edr.race_operation', :'operation', false) AS race_operation \gset
SELECT set_config('edr.race_schedule', :'schedule', false) AS race_schedule \gset
DO $verify$
DECLARE
  tenant_name text:=current_setting('edr.race_tenant');
  operation_name text:=current_setting('edr.race_operation');
  expected_count integer:=CASE current_setting('edr.race_schedule') WHEN 'auth_first' THEN 1 ELSE 0 END;
  actual_count integer;
BEGIN
  IF operation_name='operator_role' THEN
    SELECT count(*) INTO actual_count FROM public.edr_scan_jobs WHERE tenant_id=tenant_name;
    IF (SELECT role FROM public.edr_soc_operators WHERE tenant_id=tenant_name AND operator_id='scanner')<>'viewer' THEN
      RAISE EXCEPTION 'operator role change was not committed';
    END IF;
  ELSE
    SELECT count(*) INTO actual_count FROM public.edr_agent_heartbeats WHERE tenant_id=tenant_name;
    IF operation_name IN ('revoke','rotate') AND NOT EXISTS (
      SELECT 1 FROM public.edr_agent_certificates WHERE tenant_id=tenant_name
        AND fingerprint_sha256=decode(repeat('aa',32),'hex') AND revoked_at IS NOT NULL
    ) THEN RAISE EXCEPTION 'old certificate was not revoked'; END IF;
    IF operation_name='rotate' AND NOT EXISTS (
      SELECT 1 FROM public.edr_agent_certificates WHERE tenant_id=tenant_name
        AND fingerprint_sha256=decode(repeat('bb',32),'hex') AND revoked_at IS NULL
    ) THEN RAISE EXCEPTION 'replacement certificate was not enrolled'; END IF;
  END IF;
  IF actual_count<>expected_count THEN
    RAISE EXCEPTION 'certificate authorization boundary allowed/lost mutation: expected %, observed %',expected_count,actual_count;
  END IF;
END;
$verify$;
SQL
    echo "PASS: certificate authorization $operation / $schedule (observed lock wait; expected mutation count)."
  done
done
