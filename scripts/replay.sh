#!/bin/sh
set -eu
: "${EDR_DEV_TOKEN:?Set EDR_DEV_TOKEN from the backend shell first}"
ADDR="${EDR_ADDR:-127.0.0.1:8080}"
BASE="http://$ADDR/api"
curl --fail --silent --show-error -X POST "$BASE/agents" -H "Authorization: Bearer $EDR_DEV_TOKEN" -H 'Content-Type: application/json' -d '{"id":"win-lab-01","platform":"windows","group":"workstations","health":"online"}' >/dev/null
curl --fail --silent --show-error -X POST "$BASE/events" -H "Authorization: Bearer $EDR_DEV_TOKEN" -H 'Content-Type: application/json' -d '{"device_id":"win-lab-01","platform":"windows","source":"sysmon-synthetic","type":"process_create","process_guid":"{lab-process-01}","parent_process_guid":"{lab-parent-01}","image":"C:\\Windows\\System32\\notepad.exe","detail":"Synthetic demo event, not collected from Windows Sysmon"}'
printf '\nSynthetic event replayed. Refresh dashboard.\n'
