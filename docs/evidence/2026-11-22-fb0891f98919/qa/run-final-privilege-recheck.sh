#!/usr/bin/env bash
# Independent QA execution wrapper. All cluster state is disposable and local.
set +x
set -euo pipefail
: "${EDR_QA_SOURCE_ROOT:?Set immutable candidate checkout path}"
export PATH=/workspace/scratch/39b05ab721e3/toolchains/pgsql/bin:$PATH
qa_dir=$(mktemp -d /workspace/scratch/39b05ab721e3/qa-work/final-privilege-cluster.XXXXXX)
cleanup() {
  pg_ctl -D "$qa_dir/pg" -m fast stop >/dev/null 2>&1 || true
  rm -rf "$qa_dir"
}
trap cleanup EXIT
initdb -D "$qa_dir/pg" --auth-local=trust --auth-host=trust --encoding=UTF8 --no-locale > "$qa_dir/init.log"
pg_ctl -D "$qa_dir/pg" -l "$qa_dir/postgres.log" -o "-h 127.0.0.1 -p 55435 -k ''" start >/dev/null
createdb -h127.0.0.1 -p55435 edr_qa_privileges
export EDR_TEST_DATABASE_URL='postgresql://agent@127.0.0.1:55435/edr_qa_privileges?sslmode=disable'
cd "$EDR_QA_SOURCE_ROOT"
psql --version
bash scripts/test-runtime-privileges.sh
