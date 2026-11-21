#!/usr/bin/env bash
# Offline QA preflight: no database, network connection, or PostgreSQL client.
# Run from any cwd; only the dedicated local migration-chain DB is accepted.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
script="$here/test-soc-endpoint-inventory-sql.sh"
valid='postgresql://edr_chain_ci:disposable-ci-only@127.0.0.1:5432/edr_chain_test?sslmode=disable'
EDR_QA_DISPOSABLE_DB=yes EDR_TEST_DATABASE_URL="$valid" bash "$script" --preflight-only >/dev/null
EDR_QA_DISPOSABLE_DB=yes EDR_TEST_DATABASE_URL='postgresql://qa@[::1]:5432/edr_chain_test' bash "$script" --preflight-only >/dev/null

expect_denied() {
  local url="$1" flag="${2:-yes}"
  if EDR_QA_DISPOSABLE_DB="$flag" EDR_TEST_DATABASE_URL="$url" bash "$script" --preflight-only >/dev/null 2>&1; then
    echo "QA preflight accepted an unsafe target/flag" >&2
    exit 1
  fi
}
expect_denied "$valid" no
expect_denied 'postgresql://qa@db.example.com:5432/edr_chain_test'
expect_denied 'postgresql://qa@192.168.1.10:5432/edr_chain_test'
expect_denied 'postgresql://qa@127.0.0.1:5432/edr_production'
expect_denied 'postgresql://qa@127.0.0.1:5433/edr_chain_test'
expect_denied 'postgresql://qa@127.0.0.1:5432/edr_chain_test?host=db.example.com'
expect_denied 'postgresql://qa@127.0.0.1:5432/edr_chain_test?dbname=production'
expect_denied 'postgresql://qa@127.0.0.1:5432/edr_chain_test#unsafe'
expect_denied 'postgres://qa@127.0.0.1:5432/edr_chain_test'
expect_denied 'postgresql://qa@127.0.0.1:invalid/edr_chain_test'
if EDR_QA_DISPOSABLE_DB=yes EDR_TEST_DATABASE_URL="$valid" bash "$script" --unexpected >/dev/null 2>&1; then
  echo "Unexpected CLI argument was not denied" >&2
  exit 1
fi
echo "PASS: QA inventory target guard positive and negative cases (no PostgreSQL connection)"
