#!/usr/bin/env bash
# GitHub Actions ONLY. Dedicated disposable QA VM, never a production host.
set -Eeuo pipefail
cd "$(dirname "$0")/../.."
SOURCE_ROOT="$PWD"
RUN_TAG="$GITHUB_RUN_ID-$$"
QA_NETWORK="edr-qa-net-$RUN_TAG"
QA_POSTGRES="edr-qa-pg-$RUN_TAG"
PG_CLIENT_IMAGE="edr-qa-pgclient:$RUN_TAG"
FRONTEND_SNAPSHOT_SHA="0466e7c47f098ffdb83f7818eb6571e0d941aebe"
SUMMARY_FILE="$SOURCE_ROOT/qa-full-ci-results.txt"
failures=0
passes=0
postgres_started=0
network_started=0
: > "$SUMMARY_FILE"
record() { printf '%s\n' "$1" | tee -a "$SUMMARY_FILE"; }
check() {
  label="$1"; shift
  printf '::group::%s\n' "$label"
  if "$@"; then
    passes=$((passes+1)); record "PASS | $label"
    printf '::endgroup::\n'; return 0
  else
    failures=$((failures+1)); record "FAIL | $label"
    printf '::endgroup::\n'; return 1
  fi
}
cleanup() {
  if ((postgres_started)); then docker rm -f "$QA_POSTGRES" >/dev/null 2>&1 || true; fi
  if ((network_started)); then docker network rm "$QA_NETWORK" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

if [[ "$GITHUB_REPOSITORY" != "suhaylx/EDR" ]]; then
  record "FAIL | only suhaylx/EDR is authorized"; exit 2
fi
if [[ "$(git rev-parse HEAD)" != "$GITHUB_SHA" ]]; then
  record "FAIL | checkout commit is not the workflow commit"; exit 2
fi
if ! command -v docker >/dev/null || ! docker info >/dev/null 2>&1; then
  record "FAIL | isolated runner Docker Engine is unavailable"; exit 2
fi
record "SOURCE | $GITHUB_SHA"
record "BOUNDARY | dedicated QA VM only, no production host or deployment"

check "Go unit, race, vet" docker run --rm -v "$SOURCE_ROOT:/src" -w /src/backend \
  golang:1.25-bookworm bash -euo pipefail -c \
  'go version; go test ./...; go test -race -count=1 ./...; go vet ./...' || true

check "Rust Linux all-target tests and check" docker run --rm -v "$SOURCE_ROOT:/src" -w /src \
  rust:1-bookworm bash -euo pipefail -c \
  'rustc --version; cargo test --manifest-path agent/Cargo.toml --all-targets; cargo check --manifest-path agent/Cargo.toml --all-targets' || true

check "Rust Windows GNU cross-target check (NOT native Windows)" docker run --rm -v "$SOURCE_ROOT:/src" -w /src \
  rust:1-bookworm bash -euo pipefail -c \
  'apt-get update -qq; apt-get install -y --no-install-recommends gcc-mingw-w64-x86-64; rustup target add x86_64-pc-windows-gnu; cargo check --manifest-path agent/Cargo.toml --target x86_64-pc-windows-gnu --all-targets' || true

check "Go-served UI JS syntax and Node tests" docker run --rm -v "$SOURCE_ROOT:/src" -w /src \
  node:22-bookworm bash -euo pipefail -c '
    test -f backend/web/app.js
    for file in backend/web/*.js; do
      test -f "$file" || continue
      node --check "$file"
    done
    if compgen -G "backend/web/*.test.js" >/dev/null; then
      node --test backend/web/*.test.js
    else echo "NOT RUN | no Go-served Node test files at this SHA"; fi' || true

if [[ -f "$SOURCE_ROOT/frontend/package.json" ]]; then
  check "React at current source commit" docker run --rm -v "$SOURCE_ROOT:/src" -w /src/frontend \
    node:22-bookworm bash -euo pipefail -c \
    'npm install --no-audit --no-fund; npm run typecheck; npm test; npm run build' || true
else
  record "NOT INTEGRATED | React absent from current SOC backend SHA"
  if [[ -f "$SOURCE_ROOT/_frontend_lab_snapshot/frontend/package.json" ]] &&
     [[ "$(git -C "$SOURCE_ROOT/_frontend_lab_snapshot" rev-parse HEAD)" == "$FRONTEND_SNAPSHOT_SHA" ]]; then
    check "Separate React lab snapshot at $FRONTEND_SNAPSHOT_SHA" docker run --rm \
      -v "$SOURCE_ROOT:/src" -w /src/_frontend_lab_snapshot/frontend node:22-bookworm \
      bash -euo pipefail -c \
      'npm install --no-audit --no-fund; npm run typecheck; npm test; npm run build' || true
  else
    failures=$((failures+1)); record "FAIL | separate React checkout missing or wrong SHA"
  fi
fi

if check "Build disposable PostgreSQL 16 test-client image" \
    docker build -q -f scripts/ci/Dockerfile.postgres-client -t "$PG_CLIENT_IMAGE" .; then
  if check "Create internal PostgreSQL network" docker network create --internal "$QA_NETWORK"; then
    network_started=1
    if check "Start disposable PostgreSQL 16" docker run -d --rm \
       --network "$QA_NETWORK" --name "$QA_POSTGRES" \
       -e POSTGRES_USER=edr_ci -e POSTGRES_PASSWORD=disposable-ci-only \
       -e POSTGRES_DB=postgres postgres:16-alpine; then
      postgres_started=1
    fi
  fi
fi

wait_for_postgres() {
  for i in $(seq 1 40); do
    if docker exec "$QA_POSTGRES" pg_isready -U edr_ci -d postgres >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  docker logs --tail 50 "$QA_POSTGRES" >&2 || true
  return 1
}
run_db() {
  db="qa_$1"; suite="$2"
  docker exec "$QA_POSTGRES" psql -X -U edr_ci -d postgres \
    -v ON_ERROR_STOP=1 -c "CREATE DATABASE $db" || return 1
  docker run --rm --network "$QA_NETWORK" -v "$SOURCE_ROOT:/src" -w /src \
    -e "EDR_TEST_DATABASE_URL=postgresql://edr_ci:disposable-ci-only@$QA_POSTGRES:5432/$db?sslmode=disable" \
    -e EDR_QA_DISPOSABLE_DB=yes "$PG_CLIENT_IMAGE" bash -euo pipefail -c "$suite"
}
restart_db() {
  docker exec "$QA_POSTGRES" psql -X -U edr_ci -d postgres -v ON_ERROR_STOP=1 \
    -c 'CREATE DATABASE qa_restart' || return 1
  docker exec "$QA_POSTGRES" psql -X -U edr_ci -d qa_restart -v ON_ERROR_STOP=1 \
    -c "CREATE TABLE qa_restart_marker(v text); INSERT INTO qa_restart_marker VALUES ('persisted');" || return 1
  docker restart "$QA_POSTGRES" || return 1
  wait_for_postgres || return 1
  got="$(docker exec "$QA_POSTGRES" psql -X -A -t -U edr_ci -d qa_restart -v ON_ERROR_STOP=1 -c 'SELECT v FROM qa_restart_marker')" || return 1
  [[ "$got" == "persisted" ]]
}
if ((postgres_started)); then
  if check "PostgreSQL service ready" wait_for_postgres; then
    check "PostgreSQL 0001-0012 migration chain + real SOC inventory SQL" run_db chain '
      bash scripts/test-postgres-migration-chain.sh
      psql "$EDR_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f scripts/test-scan-job-results.sql
      if [[ -f scripts/test-soc-endpoint-inventory-sql.sh ]]; then
        bash scripts/test-soc-endpoint-inventory-sql.sh
      else echo "NOT RUN | SOC inventory query test absent from this SHA"; fi' || true
    check "PostgreSQL scan queue + lease renewal" run_db queue '
      bash scripts/test-scan-job-queue.sh
      bash scripts/test-scan-job-lease-renewal.sh
      if [[ -f scripts/test-scan-job-claim-revocation-race.sh ]]; then
        bash scripts/test-scan-job-claim-revocation-race.sh
      else echo "NOT RUN | claim/revocation race absent from this SHA"; fi' || true
    check "PostgreSQL enrollment constraints" run_db enrollment \
      'bash scripts/test-enrollment-migration.sh' || true
    check "PostgreSQL atomic enrollment" run_db atomic \
      'bash scripts/test-atomic-agent-enrollment.sh' || true
    check "PostgreSQL enrollment challenge replay" run_db challenges \
      'bash scripts/test-enrollment-challenges.sh' || true
    check "PostgreSQL revocation + append-only audit" run_db revocation \
      'bash scripts/test-enrollment-revocation.sh' || true
    check "PostgreSQL certificate rotation" run_db rotation '
      bash scripts/test-certificate-rotation.sh
      if [[ -f scripts/test-certificate-rotation-tenant-race.sh ]]; then
        bash scripts/test-certificate-rotation-tenant-race.sh
      else echo "NOT RUN | tenant/rotation race absent from this SHA"; fi' || true
    check "Actual disposable PostgreSQL restart and committed-row persistence" restart_db || true
  else
    failures=$((failures+1)); record "FAIL | PostgreSQL integration unavailable"
  fi
else
  failures=$((failures+1)); record "FAIL | PostgreSQL setup unavailable, database suites NOT RUN"
fi
record "NOT RUN | native Windows/Sysmon and EICAR official ClamAV host tests"
record "NOT RUN | browser accessibility and local desktop crash isolation"
record "NOT RUN | production mTLS agent startup, AD/LDAPS and signed installer"
record "TOTAL | $passes checks PASS; $failures checks FAIL"
if ((failures > 0)); then exit 1; fi
