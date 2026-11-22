# Exact candidate CI and release evidence

`candidate-ci.yml` checks every component out at
`${{ github.event.pull_request.head.sha || github.sha }}`. GitHub's default
pull-request checkout is a synthetic merge commit, so `GITHUB_SHA` alone is
not the identity of a PR head. The workflow uses the event's immutable head
SHA and the executable check wrapper verifies the checked-out commit before
and after each suite. It refuses tracked source changes.

Every required job must execute and succeed for **the same current candidate
SHA**. A skipped/cancelled job fails the aggregate gate. An old passing run,
a draft PR, a workflow dispatch request or a successful syntax check is not
evidence that the candidate executed successfully.

## Required jobs

| Job | Executed evidence |
| --- | --- |
| Backend | Go build, uncached tests, race tests and vet, with real driver and `edrd` entry point present. |
| Rust Linux and Windows | Native build, tests and check with committed `Cargo.lock` and `--locked`. Cross-compilation is not substituted for native Windows execution. |
| Frontend | Committed React tree and lockfile, `npm ci`, typecheck, tests, build and Playwright browser accessibility/auth/unknown-state tests. No historical frontend checkout is accepted. |
| PostgreSQL | Real PostgreSQL 16 migrations, actual Go inventory SQL, enrollment/revocation/rotation, queue/result/replay/exhaustion/concurrency tests, restricted runtime/registry login tests and actual service restart. |
| Integration | Builds the current Go service, Rust endpoint and React assets; requires `scripts/test-integrated-candidate.sh` to exercise the authenticated integrated candidate. |
| Release tools | Cryptographic tamper/wrong-key/wrong-SHA rejection and POSIX atomic-switch/rollback regressions. Test keys and filesystem callbacks do not count as organization signing or host rollback acceptance. |

The PostgreSQL harness deliberately fails if any required script is absent.
It creates fresh database names and never drops or adopts an existing database.
The actual inventory query test preserves its strict local `edr_chain_test`
target guard. Restricted role tests have their own fresh database.

`candidate-check.py` records source SHA, workflow SHA, run URL/attempt, OS,
command arguments, timestamps and exit codes in `.quality-evidence/`.
Artifacts are uploaded even after failure. A failed test produces a failed
ledger; absent tooling is not recorded as a passing check.

## Local PostgreSQL execution

Use an isolated PostgreSQL 16 cluster, listening only on `127.0.0.1:5432`.
The administrative fixture account must be permitted to create disposable
databases and test roles. Set `PGUSER`, `PGPASSWORD` when needed,
`PGHOST=127.0.0.1`, `PGPORT=5432`, `EDR_QA_DISPOSABLE_DB=yes`, and
`EDR_CANDIDATE_SHA` to the full committed candidate SHA. Never print connection
secrets.

```sh
python scripts/ci/candidate-check.py postgres
python scripts/ci/candidate-check.py postgres-seed
# Restart only the disposable test PostgreSQL instance here.
python scripts/ci/candidate-check.py postgres-verify
```

The final phase compares `pg_postmaster_start_time()` before and after the
restart, then checks committed challenge consumption and scan queue state.
Calling verification without a real restart fails. The GitHub workflow uses
the exact container ID supplied by `job.services.postgres.id`.

## Package staging and signing

Build from a native runner for the selected OS. The packager exports the
committed Git tree into a clean temporary build directory; local credentials,
untracked files and old binaries are excluded. It bundles `edrd`, the Rust
agent, React assets, migrations, restricted-role bootstrap and the installation
manual. It does not bundle database passwords, private keys or endpoint
identity material.

```sh
python scripts/release/package-candidate.py build \
  --candidate-sha FULL_COMMIT_SHA --target linux-x86_64 \
  --output /absolute/path/outside/repository --stage-only
```

This explicitly produces an **unsigned portable engineering candidate**.
It is not a service installer and does not establish host acceptance.

For an approved signing identity, omit `--stage-only` and supply
`--signer-hook /approved/executable` and `--trusted-key /independently/provisioned/public.pem`.
The signer receives the manifest path and output signature path as separate
arguments. The manifest binds the exact archive digest, candidate commit and
file inventory. The hook must return a raw signature accepted by
`openssl dgst -sha256 -verify`. Keys are not created by this workflow.

On native Windows, signed builds additionally require
`--authenticode-hook` and an approved `--windows-signer-thumbprint`.
Both executable signatures must have native `Get-AuthenticodeSignature`
status `Valid` and match that publisher before the archive is created.

```sh
python scripts/release/package-candidate.py verify \
  --archive candidate.tar.gz --manifest candidate.manifest.json \
  --signature candidate.manifest.sig \
  --trusted-key /independently/provisioned/public.pem \
  --expected-sha FULL_COMMIT_SHA
```

Obtain the expected SHA and public-key fingerprint through the approved
release channel. Never trust a public key merely because it accompanies a
downloaded package. Verification validates signature and bytes; it does not
grant deployment approval.

## Rollback and remaining gates

`release_switch.py` is a POSIX primitive for a caller that has already verified
the package and obtained deployment approval. It uses an exclusive lock,
durable activation journal and atomic symlink replacement. Failed candidate
restart or health checks restore the previous release, restart it, and require
its health check to pass. A failed restoration is explicitly reported as
`rollback_failed`. Pending/failed journals require operator recovery; a later
activation cannot silently overwrite them. It never changes database schema.

The regression suite proves these filesystem and callback semantics. Actual
service upgrade/downgrade, database compatibility, Windows activation,
credential preservation and host reboot acceptance must be tested on the
designated Windows/Linux hosts with the real packages. Native CI is separate
from those deployment-host tests.

Before deployment, attach current exact-SHA GitHub CI, independent QA verdict,
explicit InfoSec approval, signed package identity, Windows/Linux acceptance
records, actual service rollback evidence and deployment authorization. This
repository workflow neither grants those approvals nor deploys automatically.

## Workflow reference

GitHub documents exact PR head checkout in [workflow trigger semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request)
and [actions/checkout](https://github.com/actions/checkout#checkout-pull-request-head-commit-instead-of-merge-commit).
