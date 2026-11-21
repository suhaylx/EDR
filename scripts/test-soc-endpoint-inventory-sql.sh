#!/usr/bin/env bash
# QA/SOC P0: execute the ACTUAL Go inventory query strings against an empty,
# disposable PostgreSQL 16 migration-chain test database. Never run on a host DB.
set -euo pipefail
: "${EDR_TEST_DATABASE_URL:?Use disposable PostgreSQL connection URL}"
if [[ "${EDR_QA_DISPOSABLE_DB:-}" != "yes" ]]; then
  echo "EDR_QA_DISPOSABLE_DB=yes is required" >&2
  exit 2
fi
command -v python3 >/dev/null
command -v psql >/dev/null
python3 - <<'PY' | psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1
import pathlib
import re
source = pathlib.Path("backend/internal/edr/soc_endpoint_inventory.go").read_text()
def raw(name, prefix=""):
    pattern = r"const\s+" + re.escape(name) + r"\s*=\s*" + re.escape(prefix) + r"\s*`([^`]*)`"
    match = re.search(pattern, source, re.S)
    if not match:
        raise SystemExit("Cannot extract actual Go SQL query: " + name)
    return match.group(1)
cte = raw("endpointInventoryCTE")
queries = {
    "list": cte + raw("listEndpointsSQL", "endpointInventoryCTE+"),
    "detail": cte + raw("getEndpointSQL", "endpointInventoryCTE+"),
    "summary": cte + raw("summaryEndpointsSQL", "endpointInventoryCTE+"),
}
args = {
    "list": ["'qa-soc-cte-a'", "''", "''", "10", "0"],
    "detail": ["'qa-soc-cte-a'", "'win01'"],
    "summary": ["'qa-soc-cte-a'"],
}
print("BEGIN;")
print("""INSERT INTO edr_tenants(tenant_id,display_name)
VALUES ('qa-soc-cte-a','QA SQL projection A'),
       ('qa-soc-cte-b','QA SQL projection B');
INSERT INTO edr_agents(tenant_id,agent_id,platform)
VALUES ('qa-soc-cte-a','win01','windows'),
       ('qa-soc-cte-b','win01','windows');
INSERT INTO edr_agent_heartbeats(
tenant_id,agent_id,platform,agent_version,clamav_version,
signature_version,scan_ready)
VALUES ('qa-soc-cte-a','win01','windows','qa-v1','qa-clamd',
'qa-signatures',true),
('qa-soc-cte-b','win01','windows','other-v1','other-clamd',
'other-signatures',true);""")
for name, sql in queries.items():
    # Substitute the known QA-only fixture literals into the real compiled
    # query, avoiding a duplicated synthetic SQL projection.
    q = re.sub(r"\$([1-5])", lambda m: args[name][int(m.group(1)) - 1], sql)
    print("CREATE TEMP VIEW qa_inventory_" + name + " AS " + q + ";")
print("""DO $qa$
BEGIN
  IF (SELECT count(*) FROM qa_inventory_list) <> 1 OR
     NOT EXISTS (
       SELECT 1 FROM qa_inventory_list
       WHERE agent_id='win01' AND platform='windows'
         AND agent_version='qa-v1' AND clamav_version='qa-clamd'
         AND signature_version='qa-signatures' AND scan_ready=true
         AND received_count=1 AND health='online') THEN
    RAISE EXCEPTION 'SOC inventory list CTE projection or tenant scope invalid';
  END IF;
  IF (SELECT count(*) FROM qa_inventory_detail) <> 1 OR
     NOT EXISTS (SELECT 1 FROM qa_inventory_detail
       WHERE agent_id='win01' AND agent_version='qa-v1') THEN
    RAISE EXCEPTION 'SOC inventory detail CTE projection invalid';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM qa_inventory_summary
      WHERE total=1 AND windows=1 AND linux=0
        AND online=1 AND degraded=0 AND stale=0
        AND unseen=0 AND revoked=0) THEN
    RAISE EXCEPTION 'SOC fleet summary or cross-tenant scope invalid';
  END IF;
END $qa$;
ROLLBACK;""")
PY
echo "SOC inventory list/detail/summary query projections passed disposable PostgreSQL"
