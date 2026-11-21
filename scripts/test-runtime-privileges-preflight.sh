#!/usr/bin/env bash
# Validate fixture target refusal before psql can connect or mutate a database.
set -euo pipefail
cd "$(dirname "$0")/.."
script=scripts/test-runtime-privileges.sh
valid='postgresql://qa@127.0.0.1:5432/edr_candidate_grants?sslmode=disable'
unset PGHOSTADDR PGSERVICE PGSERVICEFILE
passed=0

accept() {
  EDR_QA_DISPOSABLE_DB=yes EDR_TEST_DATABASE_URL="$1" bash "$script" --preflight-only >/dev/null
  passed=$((passed + 1))
}
reject() {
  if EDR_QA_DISPOSABLE_DB="$1" EDR_TEST_DATABASE_URL="$2" \
    bash "$script" --preflight-only >/dev/null 2>&1; then
    echo 'FAIL: unsafe runtime privilege fixture target was accepted' >&2
    exit 1
  fi
  passed=$((passed + 1))
}

accept "$valid"
accept 'postgresql://qa@[::1]:5432/edr_grants_test'
accept 'postgresql://qa@127.0.0.1:6543/edr_port_mapped_test'
reject no "$valid"
reject '' "$valid"
for target in \
  'postgresql://qa@192.0.2.1:5432/edr_test' \
  'postgresql://qa@localhost:5432/edr_test' \
  'postgresql://qa@127.0.0.1/edr_test' \
  'postgresql://qa@127.0.0.1:0/edr_test' \
  'postgresql://qa@127.0.0.1:65536/edr_test' \
  'postgresql://qa@127.0.0.1:5432/production' \
  'postgresql://qa@127.0.0.1:5432/edr_test/other' \
  'postgresql://qa@127.0.0.1:5432/edr_test%2Fother' \
  'postgresql://qa@127.0.0.1:5432/edr_test?hostaddr=192.0.2.1' \
  'postgresql://qa@127.0.0.1:5432/edr_test?sslmode=disable&host=192.0.2.1' \
  'postgresql://qa@127.0.0.1:5432/edr_test?service=remote' \
  'postgresql://qa@127.0.0.1:5432/edr_test?dbname=production' \
  'postgresql://qa@127.0.0.1:5432/edr_test#fragment' \
  'postgresql://qa@127.0.0.1,192.0.2.1:5432/edr_test' \
  'postgresql://qa@%2Fvar%2Frun%2Fpostgresql:5432/edr_test' \
  'postgresql://127.0.0.1:5432/edr_test' \
  'host=127.0.0.1 port=5432 dbname=edr_test user=qa' \
  $'postgresql://qa@127.0.0.1:5432/edr_test\n'; do
  reject yes "$target"
done
for override in PGHOSTADDR PGSERVICE PGSERVICEFILE; do
  if env "$override=unexpected" EDR_QA_DISPOSABLE_DB=yes EDR_TEST_DATABASE_URL="$valid" \
    bash "$script" --preflight-only >/dev/null 2>&1; then
    echo 'FAIL: inherited connection override was accepted' >&2
    exit 1
  fi
  passed=$((passed + 1))
done
if EDR_QA_DISPOSABLE_DB=yes EDR_TEST_DATABASE_URL="$valid" \
  bash "$script" --unexpected >/dev/null 2>&1; then
  echo 'FAIL: unexpected argument was accepted' >&2
  exit 1
fi
passed=$((passed + 1))
echo "PASS: $passed runtime privilege target checks (no PostgreSQL connection)"
