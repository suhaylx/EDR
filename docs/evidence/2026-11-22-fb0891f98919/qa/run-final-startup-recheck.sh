#!/usr/bin/env bash
set -euo pipefail
: "${EDR_QA_SOURCE_ROOT:?Set immutable candidate checkout path}"
export PATH=/workspace/scratch/39b05ab721e3/toolchains/pgsql/bin:/workspace/scratch/39b05ab721e3/toolchains/go/bin:$PATH
qa_dir=$(mktemp -d /workspace/scratch/39b05ab721e3/qa-work/final-startup-clusters.XXXXXX)
cleanup(){ for n in 1 2; do pg_ctl -D "$qa_dir/pg$n" -m fast stop >/dev/null 2>&1 || true; done; rm -rf "$qa_dir"; }
trap cleanup EXIT
for n in 1 2; do
 initdb -D "$qa_dir/pg$n" --auth-local=trust --auth-host=trust --encoding=UTF8 --no-locale > "$qa_dir/init$n.log"
 port=$((55430+n))
 pg_ctl -D "$qa_dir/pg$n" -l "$qa_dir/pg$n.log" -o "-h 127.0.0.1 -p $port -k ''" start >/dev/null
 createdb -h127.0.0.1 -p"$port" edr_same_name
 psql -h127.0.0.1 -p"$port" -d edr_same_name -X -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE ROLE qa_registry LOGIN INHERIT;
CREATE ROLE qa_runtime LOGIN INHERIT;
SQL
 for migration in "$EDR_QA_SOURCE_ROOT"/backend/migrations/*.up.sql; do
  psql -h127.0.0.1 -p"$port" -d edr_same_name -X -q -v ON_ERROR_STOP=1 -f "$migration" >/dev/null
 done
 psql -h127.0.0.1 -p"$port" -d edr_same_name -X -q -v ON_ERROR_STOP=1 -v runtime_login=qa_runtime -v registry_login=qa_registry -v dedicated_edr_database=true -f "$EDR_QA_SOURCE_ROOT/backend/bootstrap/runtime_privileges.sql" >/dev/null
done
createdb -h127.0.0.1 -p55431 --template=edr_same_name edr_no_marker
psql -h127.0.0.1 -p55431 -d edr_no_marker -X -q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
REVOKE TEMP ON DATABASE edr_no_marker FROM PUBLIC;
DELETE FROM public.edr_schema_capabilities WHERE capability='scan_lease_wallclock';
DO $old_schema$
DECLARE signature text;
BEGIN
 FOREACH signature IN ARRAY ARRAY[
 'public.edr_claim_scan_job(varchar,varchar,text,uuid,integer)',
 'public.edr_complete_scan_job(varchar,varchar,uuid,uuid,boolean)',
 'public.edr_recover_expired_scan_jobs(integer)',
 'public.edr_renew_scan_job_lease(varchar,varchar,uuid,text,uuid,integer)',
 'public.edr_complete_scan_job_with_result(varchar,varchar,uuid,uuid,text,text,text)'
 ] LOOP
  EXECUTE replace(pg_get_functiondef(to_regprocedure(signature)),'clock_timestamp()','transaction_timestamp()');
 END LOOP;
END;
$old_schema$;
SQL
createdb -h127.0.0.1 -p55431 --template=edr_same_name edr_wrong_marker
psql -h127.0.0.1 -p55431 -d edr_wrong_marker -X -q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
REVOKE TEMP ON DATABASE edr_wrong_marker FROM PUBLIC;
UPDATE public.edr_schema_capabilities SET version=2 WHERE capability='scan_lease_wallclock';
SQL
createdb -h127.0.0.1 -p55431 edr_empty_name
psql -h127.0.0.1 -p55431 -d edr_empty_name -X -q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE TEMP ON DATABASE edr_empty_name FROM PUBLIC;
SQL
export QA_REGISTRY_DSN='postgresql://qa_registry@127.0.0.1:55431/edr_same_name?sslmode=disable'
export QA_RUNTIME_DSN='postgresql://qa_runtime@127.0.0.1:55431/edr_same_name?sslmode=disable'
export QA_OTHER_RUNTIME_DSN='postgresql://qa_runtime@127.0.0.1:55432/edr_same_name?sslmode=disable'
export QA_EMPTY_REGISTRY_DSN='postgresql://qa_registry@127.0.0.1:55431/edr_empty_name?sslmode=disable'
export QA_EMPTY_RUNTIME_DSN='postgresql://qa_runtime@127.0.0.1:55431/edr_empty_name?sslmode=disable'
export QA_OLD_REGISTRY_DSN='postgresql://qa_registry@127.0.0.1:55431/edr_no_marker?sslmode=disable'
export QA_OLD_RUNTIME_DSN='postgresql://qa_runtime@127.0.0.1:55431/edr_no_marker?sslmode=disable'
export QA_WRONG_REGISTRY_DSN='postgresql://qa_registry@127.0.0.1:55431/edr_wrong_marker?sslmode=disable'
export QA_WRONG_RUNTIME_DSN='postgresql://qa_runtime@127.0.0.1:55431/edr_wrong_marker?sslmode=disable'
cd "$EDR_QA_SOURCE_ROOT/backend"
go test -race -count=1 -run '^(TestQARejects|TestQAValidMigratedStartupControl)' -v ./cmd/edrd
