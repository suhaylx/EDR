# TuranSec EDR

TuranSec combines a Go/PostgreSQL control service, one Rust endpoint binary and
the original React SOC. The current code provides authenticated engineering
workflows; release acceptance and deployment authorization depend on the exact
candidate evidence. Read the [installation manual](docs/INSTALLATION.md) and
[release file guide](docs/release/BUILD_RELEASE_FILES.md) before staging a package.

## Current components

| Component | Implemented behavior |
|---|---|
| Go `edrd` service | Separate agent and operator TLS 1.3/mTLS listeners, enrolled certificate/tenant checks, restricted PostgreSQL logins, transactional authorization and commit-before-response behavior |
| PostgreSQL | Enrollment and revocation records, persistent scan jobs and results, heartbeats, alert/case activity, ordered migrations and mandatory scan-lease and enrollment clock capabilities |
| Rust endpoint | One binary for authenticated heartbeat, job claim/renew/result operations and bounded regular-file ClamAV scans; separately labelled legacy telemetry modes |
| React SOC | Same-origin operator authentication, fleet/endpoint/alert/case views, explicit unknown/degraded/error states and role-aware controls backed by the existing API |
| Linux operation | Versioned release staging and service tooling; approved PKI, database identities, scanner dependencies and host acceptance must be provisioned separately |
| Verification | Exact-commit Go/Rust/React/PostgreSQL checks, integrated mTLS harness, independent review records, package-integrity and rollback tests |

The authenticated service uses numeric loopback listeners. Authorized remote
endpoints require a reviewed encrypted tunnel and valid enrolled certificates.
Do not expose the legacy shared-token demonstration or the unauthenticated clamd
protocol to the network.

## Build and test one source commit

Required tools: Go 1.25+, the committed Rust toolchain and `Cargo.lock`, Node
22.12+ with the npm lockfile, PostgreSQL 16, Python 3 and OpenSSL. Native Windows
testing requires an actual Windows runner; a Linux build does not establish it.

```sh
git checkout --detach FULL_REVIEWED_COMMIT_SHA
export EDR_CANDIDATE_SHA="$(git rev-parse HEAD)"
python3 scripts/ci/candidate-check.py backend
python3 scripts/ci/candidate-check.py rust
python3 scripts/ci/candidate-check.py frontend
python3 scripts/ci/candidate-check.py release-tools
```

The wrappers require a clean checkout and retain command exit statuses. Use the
documented disposable PostgreSQL setup for the SQL, restart and integration
phases. Missing runners, denied Unix sockets and unavailable browsers remain
failed or blocked checks; they are not converted into passes.

## Generate a release file

Build from the reviewed committed source on the target native OS:

```sh
python3 scripts/release/package-candidate.py build \
  --candidate-sha "$EDR_CANDIDATE_SHA" --target linux-x86_64 \
  --output /absolute/empty/release-files --stage-only
python3 scripts/release/prepare-release.py \
  --directory /absolute/empty/release-files --version v0.1.0-rc.1 \
  --source-sha "$EDR_CANDIDATE_SHA" --require-target linux-x86_64
```

This creates an explicitly **unsigned engineering archive**, its file manifest,
checksums and release notes. Both binary version strings identify the source
commit. The release workflow can build native Linux and Windows packages and,
when explicitly requested, attach them to a draft prerelease. Approved publisher
signatures and native service acceptance are separate requirements.

## Acceptance boundaries

The current candidate must not be represented as a feature-complete enterprise
EDR or approved production release. Remaining acceptance includes real authorized
Windows/Ubuntu service and Sysmon evidence, complete verified ClamAV databases,
the actual scanner-to-backend-to-SOC path, browser accessibility/authentication,
trusted package signatures and installed-service/database rollback.

Path scanning is bounded and preserves clean-by-signature, malicious, error and
unscanned distinctions. A daemon PONG is only a liveness observation. Quick/full
scan profiles, quarantine/restore, tamper protection, signed policy maintenance,
native tray/privileged IPC and AD/LDAPS deployment are not established by the
current integration or package. The manual identifies implemented operations
and the required approval gates.

## Separate development demonstrations

`backend/cmd/server`, `backend/web` and the explicit React `/lab/` UI retain
legacy loopback development behavior. Their shared-token/in-memory telemetry
does not acquire the authenticated service's persistence or identity guarantees.
The lab quickstarts remain useful for those demonstrations only; use
`backend/cmd/edrd` and the installation manual for the PostgreSQL/mTLS candidate.

## Delivery records

- [Remaining Days 4–7 checklist](docs/sprints/REMAINING_DAYS_4_7.md)
- [Dashboard and Windows and Linux installation manual](docs/INSTALLATION.md)
- [Dashboard setup](docs/INSTALLATION.md#dashboard-and-backend-installation)
- [Linux endpoint setup](docs/INSTALLATION.md#linux-endpoint-installation)
- [Windows endpoint setup](docs/INSTALLATION.md#windows-endpoint-installation)
- [Exact-candidate CI](docs/qa/CANDIDATE_CI.md)
- [Host acceptance](docs/HOST_ACCEPTANCE.md)
- [Security functionality requirements](docs/security/security-functionality-spec.md)
- [Project management and authorization](docs/PM_MANUAL.md)

Historical daily reports and accelerated-sprint documents describe their named
snapshots. Current completion requires the reviewed commit, actual tests and
explicit acceptance, followed by the deployment owner's authorization.
