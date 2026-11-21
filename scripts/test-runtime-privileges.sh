#!/usr/bin/env bash
# Real PostgreSQL tests in an EMPTY, disposable, loopback EDR test database.
# Run from the repository root. EDR_TEST_DATABASE_URL is the administrative
# fixture connection; it is never printed. Existing edr_ci_candidate is allowed.
set +x
set -euo pipefail
if ! [[ -v EDR_TEST_DATABASE_URL ]] || [[ -z "$EDR_TEST_DATABASE_URL" ]]; then
  echo 'EDR_TEST_DATABASE_URL must name an empty disposable PostgreSQL database' >&2
  exit 2
fi
command -v psql >/dev/null
command -v python3 >/dev/null

connection_info="$(psql "$EDR_TEST_DATABASE_URL" -X -qAt -v ON_ERROR_STOP=1 \
  -F '|' -c "SELECT current_database(),inet_server_addr(),inet_server_port(),current_user")"
IFS='|' read -r test_database test_host test_port admin_login <<< "$connection_info"
if ! [[ "$test_database" =~ ^edr_[a-z0-9_]+$ ]] ||
   ! [[ "$test_host" == "127.0.0.1" || "$test_host" == "::1" ]] ||
   ! [[ "$test_port" =~ ^[0-9]+$ ]]; then
  echo 'Refusing tests outside a disposable edr_* database on loopback TCP' >&2
  exit 2
fi
existing="$(psql "$EDR_TEST_DATABASE_URL" -X -qAt -v ON_ERROR_STOP=1 \
  -c "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname IN ('edr_tenants','edr_agents','edr_scan_jobs','edr_soc_operators')")"
if [[ "$existing" != "0" ]]; then
  echo 'Refusing runtime privilege test in a database with existing EDR tables' >&2
  exit 2
fi

test_suffix="$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
runtime_login="edr_grant_runtime_$test_suffix"
registry_login="edr_grant_registry_$test_suffix"
export EDR_GRANT_TEST_PASSWORD
EDR_GRANT_TEST_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
runtime_connection="host=$test_host port=$test_port dbname=$test_database user=$runtime_login connect_timeout=5"
registry_connection="host=$test_host port=$test_port dbname=$test_database user=$registry_login connect_timeout=5"
test_roles_created=false
cleanup() {
  # These randomly named logins were created by this test, never supplied by an
  # operator. Drop only their grants in this disposable DB, then the logins.
  if [[ "$test_roles_created" == true ]]; then
    psql "$EDR_TEST_DATABASE_URL" -X -q -v ON_ERROR_STOP=1 \
      -v runtime_login="$runtime_login" -v registry_login="$registry_login" \
      >/dev/null 2>&1 <<'SQL' || true
\set ECHO none
SELECT format('DROP OWNED BY %I,%I', :'runtime_login', :'registry_login') \gexec
SELECT format('DROP ROLE %I,%I', :'runtime_login', :'registry_login') \gexec
SQL
  fi
  unset EDR_GRANT_TEST_PASSWORD
}
trap cleanup EXIT

for migration in \
  0001_agent_enrollment \
  0002_enrollment_audit_guard \
  0003_certificate_rotation \
  0004_enrollment_challenges \
  0005_scan_job_queue \
  0006_atomic_agent_enrollment \
  0007_scan_job_lease_renewal \
  0008_scan_job_results \
  0009_agent_heartbeats \
  0010_soc_operator_scan_jobs \
  0011_soc_malware_alerts \
  0012_soc_alert_activity \
  0013_scan_lease_wallclock; do
  psql "$EDR_TEST_DATABASE_URL" -X -q -v ON_ERROR_STOP=1 \
    -f "backend/migrations/$migration.up.sql" >/dev/null
done

# \getenv avoids credentials in argv, committed SQL, or echo output.
# Random-name collisions fail rather than altering an existing role.
if ! psql "$EDR_TEST_DATABASE_URL" -X -q -v ON_ERROR_STOP=1 \
  -v runtime_login="$runtime_login" -v registry_login="$registry_login" \
  >/dev/null 2>&1 <<'SQL'
\set ECHO none
\getenv fixture_password EDR_GRANT_TEST_PASSWORD
BEGIN;
-- Fixture admin is a disposable-cluster superuser. Suppress only this
-- transaction's credential SQL logging, including error statement text.
SET LOCAL log_statement='none';
SET LOCAL log_min_error_statement='panic';
SELECT format('CREATE ROLE %I LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
  :'runtime_login', :'fixture_password') \gexec
SELECT format('CREATE ROLE %I LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
  :'registry_login', :'fixture_password') \gexec
COMMIT;
SQL
then
  echo 'Failed to create isolated privilege-test logins; no credential output retained' >&2
  exit 1
fi
test_roles_created=true

psql "$EDR_TEST_DATABASE_URL" -X -q -v ON_ERROR_STOP=1 \
  -v runtime_login="$runtime_login" -v registry_login="$registry_login" \
  -v dedicated_edr_database=true -f backend/bootstrap/runtime_privileges.sql
# Reapplication must validate existing role/column state without widening grants.
psql "$EDR_TEST_DATABASE_URL" -X -q -v ON_ERROR_STOP=1 \
  -v runtime_login="$runtime_login" -v registry_login="$registry_login" \
  -v dedicated_edr_database=true -f backend/bootstrap/runtime_privileges.sql

psql "$EDR_TEST_DATABASE_URL" -X -q -v ON_ERROR_STOP=1 \
  -f scripts/test-lease-wallclock-upgrade.sql

psql "$EDR_TEST_DATABASE_URL" -X -q -v ON_ERROR_STOP=1 \
  -v runtime_login="$runtime_login" -v registry_login="$registry_login" \
  -f scripts/test-runtime-privileges-catalog.sql

# Public synthetic fixtures only. This is scanner-result protocol evidence,
# not an execution of ClamAV or a real endpoint host.
psql "$EDR_TEST_DATABASE_URL" -X -q -v ON_ERROR_STOP=1 <<'SQL'
INSERT INTO public.edr_tenants(tenant_id,display_name,disabled_at)
VALUES ('grantA','Privilege test A',NULL),('grantB','Privilege test B',NULL),
       ('grantDisabled','Disabled privilege test',now());
INSERT INTO public.edr_agents(tenant_id,agent_id,platform,revoked_at)
VALUES ('grantA','linux01','linux',NULL),('grantB','linux01','linux',NULL),
       ('grantDisabled','linux01','linux',NULL),('grantA','revoked','linux',now()),
       ('grantA','expired','linux',NULL),('grantA','future','linux',NULL);
INSERT INTO public.edr_soc_operators(tenant_id,operator_id,fingerprint_sha256,role,revoked_at)
VALUES ('grantA','scanner',decode(repeat('a1',32),'hex'),'scanner',NULL),
       ('grantA','investigator',decode(repeat('b2',32),'hex'),'scanner',NULL),
       ('grantA','viewer',decode(repeat('c3',32),'hex'),'viewer',NULL),
       ('grantA','revoked',decode(repeat('d4',32),'hex'),'scanner',now()),
       ('grantB','scanner',decode(repeat('e5',32),'hex'),'scanner',NULL),
       ('grantDisabled','scanner',decode(repeat('f6',32),'hex'),'scanner',NULL);
INSERT INTO public.edr_agent_certificates(tenant_id,agent_id,fingerprint_sha256,not_before,not_after)
VALUES ('grantA','linux01',decode(repeat('ab',32),'hex'),now()-interval '1 minute',now()+interval '1 day'),
       ('grantA','expired',decode(repeat('c1',32),'hex'),now()-interval '1 day',now()-interval '1 minute'),
       ('grantA','future',decode(repeat('c2',32),'hex'),now()+interval '1 hour',now()+interval '1 day');
SQL

# Actual restricted connections, not SET ROLE within an admin test session.
PGPASSWORD="$EDR_GRANT_TEST_PASSWORD" psql "$runtime_connection" -X -q \
  -v ON_ERROR_STOP=1 -v expected_login="$runtime_login" \
  -f scripts/test-runtime-privileges.sql
PGPASSWORD="$EDR_GRANT_TEST_PASSWORD" psql "$registry_connection" -X -q \
  -v ON_ERROR_STOP=1 -v expected_login="$registry_login" \
  -f scripts/test-registry-privileges.sql
EDR_TEST_RUNTIME_CONNECTION="$runtime_connection" \
  bash scripts/test-certificate-authorization-races.sh
EDR_TEST_RUNTIME_CONNECTION="$runtime_connection" \
  python3 scripts/test-lease-timing-races.py
echo 'PASS: live PostgreSQL restricted logins, transactional certificate authorization, lifecycle, exact grants, and denied escalation.'
