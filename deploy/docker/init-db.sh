#!/usr/bin/env bash
# postgres:16 entrypoint calls this only on an EMPTY dedicated edr database.
set -Eeuo pipefail
umask 077
for variable in EDR_RUNTIME_PASSWORD EDR_REGISTRY_PASSWORD; do
  value="${!variable:-}"
  if ! [[ "$value" =~ ^[a-f0-9]{64}$ ]]; then
    echo "Required generated database role secret is invalid" >&2
    exit 1
  fi
done
for file in /bootstrap/fingerprints/analyst.sha256 /bootstrap/fingerprints/viewer.sha256; do
  test -r "$file" || { echo "Missing public operator fingerprint" >&2; exit 1; }
  [[ "$(cat "$file")" =~ ^[a-f0-9]{64}$ ]] || exit 1
done
db() { psql --no-psqlrc -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" "$@"; }
# psql quote semantics safely handle values; secrets are restricted hex.
db -v runtime_pw="$EDR_RUNTIME_PASSWORD" -v registry_pw="$EDR_REGISTRY_PASSWORD" <<'SQL'
SELECT set_config('edr.init_runtime_pw', :'runtime_pw', false);
SELECT set_config('edr.init_registry_pw', :'registry_pw', false);
DO $body$
BEGIN
 EXECUTE format('CREATE ROLE edr_service_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
                current_setting('edr.init_runtime_pw'));
 EXECUTE format('CREATE ROLE edr_service_registry LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
                current_setting('edr.init_registry_pw'));
END
$body$;
SQL
for migration in /bootstrap/backend/migrations/*.up.sql; do
  echo "Applying $(basename "$migration")"
  db -f "$migration" >/dev/null
done
db -v runtime_login=edr_service_runtime \
   -v registry_login=edr_service_registry \
   -v dedicated_edr_database=true \
   -f /bootstrap/backend/bootstrap/runtime_privileges.sql >/dev/null
db -v analyst_fp="$(cat /bootstrap/fingerprints/analyst.sha256)" \
   -v viewer_fp="$(cat /bootstrap/fingerprints/viewer.sha256)" <<'SQL'
BEGIN;
INSERT INTO public.edr_tenants(tenant_id,display_name) VALUES ('lab','Local Docker lab');
INSERT INTO public.edr_enrollment_audit(tenant_id,event_type,actor_id)
VALUES ('lab','tenant_created','docker_lab_init');
INSERT INTO public.edr_soc_operators(tenant_id,operator_id,fingerprint_sha256,role)
VALUES ('lab','analyst',decode(:'analyst_fp','hex'),'scanner'),
       ('lab','health-viewer',decode(:'viewer_fp','hex'),'viewer');
COMMIT;
SQL
echo "Local EDR schema and operator identities ready"
