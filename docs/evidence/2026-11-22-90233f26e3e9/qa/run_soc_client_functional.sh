#!/usr/bin/env bash
set +x
set -euo pipefail
: "${QA_EDR_SOURCE:?Set candidate source root}"
qa_base=/workspace/scratch/39b05ab721e3/qa-round2
export PATH=/workspace/scratch/39b05ab721e3/toolchains/pgsql/bin:/workspace/scratch/39b05ab721e3/toolchains/go/bin:$PATH
qa_pg=$(mktemp -d "$qa_base/soc-pg.XXXXXX")
cleanup() { pg_ctl -D "$qa_pg/data" -m fast stop >/dev/null 2>&1 || true; rm -rf "$qa_pg"; }
trap cleanup EXIT
mkdir -p "$qa_base/build"
(cd "$QA_EDR_SOURCE/backend" && go build -mod=readonly -o "$qa_base/build/edrd" ./cmd/edrd)
initdb -D "$qa_pg/data" --auth-local=trust --auth-host=trust --encoding=UTF8 --no-locale > "$qa_pg/init.log"
pg_ctl -D "$qa_pg/data" -l "$qa_pg/server.log" -o "-h 127.0.0.1 -p 55439 -k ''" start >/dev/null
createdb -h127.0.0.1 -p55439 edr_qa_soc_client
export EDR_TEST_DATABASE_URL='postgresql://agent@127.0.0.1:55439/edr_qa_soc_client?sslmode=disable'
python3 "$qa_base/run_soc_client_fixture.py"
