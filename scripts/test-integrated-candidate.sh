#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${EDR_TEST_DATABASE_URL:?Use a newly created local edr_integrated_test database}"
: "${EDR_QA_DISPOSABLE_DB:?Set yes for the isolated test database}"
test "$EDR_QA_DISPOSABLE_DB" = yes
command -v go >/dev/null
command -v cargo >/dev/null
command -v psql >/dev/null
command -v openssl >/dev/null
test -f frontend/dist/index.html
mkdir -p build .quality-evidence
(cd backend && go build -mod=readonly -ldflags "-X main.sourceSHA=${EDR_CANDIDATE_SHA:-uncommitted} -X main.version=0.1.0-candidate" -o ../build/edrd ./cmd/edrd)
(cd agent && TURANSEC_BUILD_SHA="${EDR_CANDIDATE_SHA:-uncommitted}" cargo build --locked)
python3 scripts/test-integrated-candidate.py
