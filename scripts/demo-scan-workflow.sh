#!/bin/sh
set -eu
# Demonstrates the API lifecycle ONLY. It never invokes an antivirus engine.
# Do not use with live endpoints or infer malware protection from this demo.
: "${EDR_DEV_TOKEN:?Set EDR_DEV_TOKEN to the local lab API token}"
ADDR="${EDR_ADDR:-127.0.0.1:8080}"
case "$ADDR" in 127.0.0.1:*|localhost:*) ;; *) echo 'Refusing non-local lab target' >&2; exit 1;; esac
BASE="http://$ADDR/api"
AUTH="Authorization: Bearer $EDR_DEV_TOKEN"
json='Content-Type: application/json'
curl --fail --silent --show-error -X POST "$BASE/agents" -H "$AUTH" -H "$json" -d '{"id":"win-lab-01","platform":"windows","group":"lab"}' >/dev/null
curl --fail --silent --show-error -X POST "$BASE/scan-jobs" -H "$AUTH" -H "$json" -d '{"agent_id":"win-lab-01","request_id":"synthetic-demo-001","scan_type":"quick"}'
printf '\nQueued a lab-only scan command. No endpoint scanner has executed.\n'
curl --fail --silent --show-error "$BASE/scan-jobs" -H "$AUTH"
