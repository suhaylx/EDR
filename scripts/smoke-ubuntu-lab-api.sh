#!/usr/bin/env bash
# Day 3 disposable CI smoke: compiled Go binary and actual local HTTP stack.
# Does NOT access production, run malware or test real Windows/Linux agents.
set -euo pipefail
if [[ $# -ne 1 ]]; then echo "usage: bash scripts/smoke-ubuntu-lab-api.sh BINARY" >&2; exit 2; fi
binary="$(realpath "$1")"
test -x "$binary"
command -v curl >/dev/null
command -v jq >/dev/null
command -v openssl >/dev/null
port=18083
url="http://127.0.0.1:$port"
tmp="$(mktemp -d)"
pid=''
cleanup() {
  if [[ -n "$pid" ]]; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT
# Generated for this disposable run; never print or artifact the secret.
token="$(openssl rand -hex 24)"
cd "$(dirname "$0")/.."
EDR_WEB_DIR="$PWD/backend/web" EDR_ADDR="127.0.0.1:$port" EDR_DEV_TOKEN="$token" "$binary" >"$tmp/server.log" 2>&1 &
pid="$!"
for _ in $(seq 1 60); do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "Go lab backend exited before health endpoint" >&2
    sed -E 's/Bearer [^[:space:]]+/Bearer [REDACTED]/g' "$tmp/server.log" >&2
    exit 1
  fi
  if curl --noproxy '*' -fsS --max-time 1 "$url/api/health" >"$tmp/health.json" 2>/dev/null; then
    break
  fi
  sleep .2
done
jq -e '.status == "ok" and .mode == "development"' "$tmp/health.json" >/dev/null
status="$(curl --noproxy '*' -sS --max-time 5 -o "$tmp/no-auth.json" -w '%{http_code}' "$url/api/events")"
test "$status" = 401 || { echo "missing token not denied" >&2; exit 1; }
status="$(curl --noproxy '*' -sS --max-time 5 -o "$tmp/bad-auth.json" -w '%{http_code}' -H 'Authorization: Bearer wrong-token-1234567890123456' "$url/api/events")"
test "$status" = 401 || { echo "invalid token not denied" >&2; exit 1; }
# Route through real listener and storage; no handler stubs or mock response.
curl --noproxy '*' -fsS --max-time 5 \
  -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
  -X POST "$url/api/agents" \
  --data '{"id":"ci-windows-01","platform":"windows","group":"disposable-ci","health":"lab_unprotected"}' \
  >"$tmp/agent.json"
jq -e '.id=="ci-windows-01" and .platform=="windows"' "$tmp/agent.json" >/dev/null
curl --noproxy '*' -fsS --max-time 5 \
  -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
  -X POST "$url/api/events" \
  --data '{"device_id":"ci-windows-01","platform":"windows","source":"sysmon","source_provider":"Microsoft-Windows-Sysmon","source_channel":"Microsoft-Windows-Sysmon/Operational","source_event_id":22,"source_record_id":"9001","type":"dns_query","time":"2026-11-21T12:00:00Z","source_fields":{"query_name":"example.test"},"detail":"Synthetic CI event, not endpoint detection"}' \
  >"$tmp/event.json"
jq -e '.source_event_id==22 and .source_record_id=="9001" and .source_provider=="Microsoft-Windows-Sysmon" and .time_origin=="sender_reported_unverified" and .received_at!=""' "$tmp/event.json" >/dev/null
curl --noproxy '*' -fsS --max-time 5 -H "Authorization: Bearer $token" "$url/api/events" >"$tmp/events.json"
jq -e 'length==1 and .[0].source_event_id==22' "$tmp/events.json" >/dev/null
curl --noproxy '*' -fsS --max-time 5 -H "Authorization: Bearer $token" "$url/api/detections" >"$tmp/detections.json"
jq -e 'length==0' "$tmp/detections.json" >/dev/null
# Fail-closed source privacy: invalid event ID/type, forged provider and clipboard.
for body in \
 '{"device_id":"ci-windows-01","platform":"windows","source":"sysmon","source_event_id":22,"source_record_id":"9002","type":"process_create","process_guid":"{test}","image":"C:\\Windows\\System32\\cmd.exe"}' \
 '{"device_id":"ci-windows-01","platform":"windows","source":"sysmon","source_provider":"Microsoft-Windows-Security-Auditing","source_channel":"Security","source_event_id":22,"source_record_id":"9003","type":"dns_query"}' \
 '{"device_id":"ci-windows-01","platform":"windows","source":"sysmon","source_event_id":24,"source_record_id":"9004","type":"clipboard_change_metadata","file_path":"C:\\secret.txt"}'; do
  status="$(curl --noproxy '*' -sS --max-time 5 -o "$tmp/denied.json" -w '%{http_code}' \
    -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
    -X POST "$url/api/events" --data "$body")"
  test "$status" = 400 || { echo "unsafe source metadata not denied, status $status" >&2; exit 1; }
done
curl --noproxy '*' -fsS --max-time 5 -H "Authorization: Bearer $token" "$url/api/events" >"$tmp/remaining.json"
jq -e 'length==1 and .[0].source_record_id=="9001"' "$tmp/remaining.json" >/dev/null
curl --noproxy '*' -fsS --max-time 5 "$url/" >"$tmp/index.html"
grep -qi 'TuranSec' "$tmp/index.html"
# Public bind must fail immediately rather than starting an HTTP listener.
if EDR_ADDR="0.0.0.0:$port" EDR_DEV_TOKEN="$token" "$binary" >"$tmp/public.log" 2>&1; then
  echo "shared-token API permitted a public network listener" >&2
  exit 1
fi
grep -qi 'loopback' "$tmp/public.log" || { echo "binding failure explanation missing" >&2; exit 1; }
echo "PASS: compiled Go API health/auth, synthetic source ingestion, denials and served SOC UI"
echo "NOT RUN: genuine Windows Sysmon, Linux endpoint, real ClamAV, production mTLS or host deployment"
