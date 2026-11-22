# TuranSec EDR installation, verification and rollback

Updated 22 November 2026, Asia/Samarkand. This is the manual for the integrated engineering candidate. It supersedes the old shared-token quickstarts when installing the authenticated service.

## Release state and scope

The candidate provides a runnable Go/PostgreSQL mTLS service, one Rust endpoint scan client, and the original React SOC. The secure SOC supports fleet and scan evidence reads, path-scan scheduling and cancellation, and alert/case workflows. Mutations require an enrolled scanner-role operator; viewer-role access remains read-only. The explicit `/lab/` React UI and old Go dashboard remain development demonstrations with separate authentication and data.

**Deployment is NO-GO until all release gates below have exact-candidate evidence and the deployment owner approves the target and window.** Source, a portable archive, a passing unit test, and a successful TLS heartbeat do not establish endpoint protection or production readiness.

| Gate | Required evidence |
|---|---|
| Candidate identity | Full Git commit SHA, PR and dependency lockfiles; binaries and manifest agree |
| CI | Successful actual jobs at that SHA, including Go/race/vet, Linux/Windows Rust, PostgreSQL, React and browser checks |
| Trust | Explicit InfoSec review of TLS, revocation transactions, file access, detection provenance and limits |
| QA | Independent verdict on the integrated SHA and acceptance records |
| Hosts | Actual authorized Ubuntu and Windows Server 2022 host records, ClamAV/EICAR, Sysmon and UI evidence |
| Packages | Approved publisher signatures, verified checksums, installed-service rollback rehearsal |
| Deployment | Named owner authorization for the exact package, hosts, canary, window and rollback plan |

The Rust modes below are bounded CLI operations. They do not install a Windows service, configure Sysmon, supervise ClamAV, provide quarantine/restore or implement tamper protection. The local companion is a web UI; native tray packaging and privileged IPC acceptance remain separate gates. Legacy lab telemetry is not authenticated detector provenance.

## 1. Select and verify one candidate

Use a reviewed full SHA from the integration PR. Build in a clean isolated checkout, never from `main` merely because an older parent was green.

```bash
git checkout --detach FULL_REVIEWED_COMMIT_SHA
git status --porcelain
git rev-parse HEAD
```

Record the printed SHA. A nonempty status must be resolved before collecting exact-source evidence. Do not include credential files, private keys, lease tokens or connection strings in logs or attachments.

Required build tools: Go 1.25+, Rust/Cargo, Node 22.12+ with npm, PostgreSQL 16 client/server, Python 3 and OpenSSL. Use committed `backend/go.sum`, `agent/Cargo.lock` and `frontend/package-lock.json`. Linux scanning uses `openat2` and fails closed where unsupported; the policy directory and all its ancestors must be administrator controlled.

```bash
export EDR_CANDIDATE_SHA="$(git rev-parse HEAD)"
python3 scripts/ci/candidate-check.py backend
python3 scripts/ci/candidate-check.py rust
python3 scripts/ci/candidate-check.py frontend
python3 scripts/ci/candidate-check.py release-tools
```

The frontend command includes actual browser/accessibility execution. A browser download failure or launch failure is a blocked check, not a pass. Likewise, a Rust Unix-socket test that cannot run is not waived. The CI workflow records each command, source SHA, job/run identity and exit status in `.quality-evidence/`.

## 2. Provision a dedicated PostgreSQL database

Use a separate migration administrator. Neither serving credential may own the database, schema, tables or privileged functions. Provision two distinct unprivileged `LOGIN INHERIT` identities, for example `edr_service_runtime` and `edr_service_registry`, using the organization's secret manager and database authentication policy. Do not put passwords in shell history or this repository.

Connect as the migration administrator to an **empty dedicated EDR database**, then apply migrations 0001–0013 in sorted order:

```bash
for migration in backend/migrations/*.up.sql; do
  psql --dbname=edr -X -v ON_ERROR_STOP=1 -f "$migration"
done
psql --dbname=edr -X -v ON_ERROR_STOP=1 \
  -v runtime_login=edr_service_runtime \
  -v registry_login=edr_service_registry \
  -v dedicated_edr_database=true \
  -f backend/bootstrap/runtime_privileges.sql
```

Choose the host/port/administrator using a protected PostgreSQL service file or approved connection method. The commands do not create identities or enroll a tenant automatically. Provision enrollment and operator records out of band through reviewed administrative procedures, matching the SHA-256 fingerprint of each actual certificate. Never bypass enrollment by accepting a request header.

The bootstrap restricts runtime writes to audited functions and creates separate read-only registry access. It revokes default public temporary/schema/function privileges in this dedicated database. Review [RUNTIME_DATABASE_ROLES.md](backend/RUNTIME_DATABASE_ROLES.md) before applying it. Reapplication validates existing role ownership and membership; it refuses unsafe reuse.

For an existing database that has already applied 0001–0012, take and verify the approved backup, stop the serving processes in the authorized maintenance window, apply only `0013_scan_lease_wallclock.up.sql` as the migration administrator, then reapply the restricted-role bootstrap using the existing serving logins. Migration 0013 atomically replaces the lease functions while preserving their ownership, grants and security settings. It records the `scan_lease_wallclock` capability; the new service refuses to listen without version 1 of that capability. Do not rerun the initial schema migrations against an existing database. Verify migration and application compatibility before restarting; the upgrade does not grant deployment authorization.

The current service requires both handles to reach the same explicit numeric-loopback PostgreSQL address, port and database, using different logins. Remote database deployment needs a separately reviewed transport configuration. `sslmode=disable` is permitted only for this loopback candidate; enforce the approved local-host access boundary. Remote plaintext PostgreSQL is rejected.

Create two owner-only DSN files under `/etc/turansec/`: `registry.dsn` and `runtime.dsn`. Each contains one PostgreSQL URI with its own provisioned login and the same database. Keep the files outside the package and set Unix mode `0600`. Use SCRAM or the approved local database authentication mechanism; the test harness's temporary trust-authenticated cluster is not an installation setting.

## 3. Provision separate PKI identities

Obtain credentials from the approved CA workflow. Release-package signing and mTLS identity use separate trust purposes.

| File/principal | Requirements |
|---|---|
| Server certificate/key | Valid non-CA leaf, ServerAuth, digital-signature usage, matching key, SAN matching the client URL |
| Agent CA bundle | Controlled valid CA certificate(s); no overlap of signing keys with the operator CA |
| Agent client certificate | ClientAuth, one URI SAN `spiffe://turansec.local/tenants/TENANT/agents/AGENT`; enrolled exact fingerprint |
| Operator CA bundle | Separate signing keys and issuance policy from agent identities |
| Operator client certificate | ClientAuth, one URI SAN `spiffe://turansec.local/tenants/TENANT/operators/OPERATOR`; enrolled fingerprint and `viewer` or `scanner` role |

No common-name, shared bearer token, proxy header or self-declared tenant substitutes for these registrations. The service requires TLS 1.3, disables session tickets and checks the live registry on every request. Mutations recheck and lock the verified leaf/principal in the same PostgreSQL transaction as the operation; success is returned only after commit.

The integration harness generates short-lived test CAs solely inside a private temporary directory and removes them. Those certificates are not organizational credentials or release signatures.

## 4. Stage the package

On a native Linux x86_64 build machine:

```bash
python3 scripts/release/package-candidate.py build \
  --candidate-sha "$EDR_CANDIDATE_SHA" \
  --target linux-x86_64 \
  --output /absolute/staging/directory \
  --stage-only
```

This produces an explicitly **unsigned engineering archive** and a SHA-256 manifest. Linux archives include a separately invoked service installer and bounded endpoint timer; package generation does not install/start services or grant approval. See [LINUX_SERVICE_INSTALLATION.md](LINUX_SERVICE_INSTALLATION.md) for verified staging, registration, activation, upgrade and removal. Build Windows packages on a native Windows x86_64 runner with `--target windows-x86_64`.

For a signed package, omit `--stage-only` and supply the existing organizational `--signer-hook` and independently provisioned `--trusted-key`. The hook receives manifest and output-signature paths. Windows also requires `--authenticode-hook` and the approved `--windows-signer-thumbprint`; the packager verifies native Authenticode for both executables. The tool does not generate a replacement signing identity.

Verify the detached manifest signature and archive before installation:

```bash
python3 scripts/release/package-candidate.py verify \
  --archive /staging/CANDIDATE.tar.gz \
  --manifest /staging/CANDIDATE.manifest.json \
  --signature /staging/CANDIDATE.manifest.sig \
  --trusted-key /approved/trust/release-publisher.pem \
  --expected-sha "$EDR_CANDIDATE_SHA"
```

Use `--help` to confirm option names for the selected commit. Obtain the trusted public key through the approved channel, independently of the downloaded archive. A checksum alone is not publisher authentication.

## 5. Configure and start the candidate on an approved lab host

Extract the verified version to a new immutable directory under `/opt/turansec/releases/FULL_SHA/`. Retain the previous verified release. The package contains `bin/edrd`, `bin/turansec-edr-agent`, `web/`, `backend/migrations/`, `backend/bootstrap/` and this manual. The database commands above use the same relative paths from either the source checkout or the extracted archive root. Configure `/opt/turansec/current` to the reviewed release only in the authorized installation window.

Copy [config/edrd.example.json](../config/edrd.example.json) to `/etc/turansec/edrd.json` and replace the certificate/key/DSN/UI paths with provisioned absolute paths. Configuration and private keys require owner-only permissions and regular non-symlink files. Public CA files may be readable; private keys and DSNs must not be. Set the built UI path to the package's `web/` directory. `EDR_SOC_UI_DIR` can override only that path.

Run as a dedicated unprivileged service identity with access to those files:

```bash
/opt/turansec/current/bin/edrd --version
/opt/turansec/current/bin/edrd --config /etc/turansec/edrd.json
```

The default listeners are `127.0.0.1:9443` for endpoints and `127.0.0.1:9444` for operators. Numeric loopback binding is mandatory. Keep PostgreSQL and ClamAV local; do not open public 5432/9443/9444/3310 as an installation shortcut. Remote authorized hosts use a reviewed encrypted tunnel. Certificates must match the client-facing URL even through a tunnel; never disable certificate verification.

For systemd, use the provided [Linux service workflow](LINUX_SERVICE_INSTALLATION.md). Its units use dynamic service identities, read-only systemd credential delivery, closed capability sets and filesystem/network restrictions. Registration does not start or enable services; activation checks the configured operator identity and the selected executable. The endpoint timer invokes the existing bounded heartbeat/scanner/batch commands. Confirm host compatibility and capture start/stop/restart/reboot evidence before enabling autostart. Direct CLI execution above remains available for an approved diagnostic session.

## 6. Enroll and verify the single Rust endpoint

Provision the endpoint identity and approved CA/key files locally. Unix private keys require mode `0600`, with no symlink or writable ancestor. Windows requires administrator-reviewed ACLs and reparse-safe file acceptance; those controls are still a release gate and are not proven by compiling an EXE.

Set these environment variables to local paths and enrolled identifiers. Do not put private PEM or bearer tokens in them:

```bash
export TURANSEC_MTLS_ORIGIN=https://127.0.0.1:9443
export TURANSEC_MTLS_TENANT_ID=ENROLLED_TENANT
export TURANSEC_MTLS_AGENT_ID=ENROLLED_AGENT
export TURANSEC_MTLS_CA_PEM=/absolute/path/server-ca.pem
export TURANSEC_MTLS_CERT_PEM=/absolute/path/agent.pem
export TURANSEC_MTLS_KEY_PEM=/absolute/path/agent.key
export TURANSEC_LAB_SCAN_ROOT=/absolute/admin-controlled/scan-root
/opt/turansec/current/bin/turansec-edr-agent --version
/opt/turansec/current/bin/turansec-edr-agent --heartbeat-mtls
/opt/turansec/current/bin/turansec-edr-agent --agent-status-mtls
```

On Windows use the corresponding PowerShell `$env:NAME` assignments and `.exe`. Connect only through the approved path to the same Go candidate. A heartbeat confirms a transport/storage operation; it is not hardware attestation, signature freshness or a protection verdict.

Provision the official ClamAV engine and signature databases separately, verify publisher/database signatures and record versions. Linux uses `/run/clamav/clamd.ctl` unless an approved absolute `TURANSEC_CLAMD_SOCKET` is set. Windows expects clamd only on `127.0.0.1:3310`. Test `--clamav-health`; a PONG proves liveness only. The endpoint supports `--scan-once-mtls` or `--scan-batch-mtls 1` through `20` for scheduled bounded jobs. It preserves `malicious`, `clean_by_signature`, `error` and `unscanned`; a clean signature scan is not proof of safety. Boolean-only completion is retired on the new service.

## 7. Open and accept the SOC

Use the approved browser profile with a valid operator client certificate and trusted server CA. Browse the tunneled/direct local HTTPS operator origin on port 9444. `/soc/v1/session` supplies the enrolled tenant/operator/role; JavaScript does not accept a bearer token or choose another tenant.

Connect to SOC and review the enrolled endpoint inventory, scan jobs, alerts and assigned cases. Scanner-role operators can request a bounded path scan, inspect its job/result, cancel a pending job, acknowledge an open alert, add case notes, assign/unassign a case, and resolve/reopen it. Resolve records the analyst's decision; it does not prove endpoint remediation. Quick/full scan profiles and quarantine are not provided by these controls.

Before a mutation, the client refreshes the authenticated session and relevant target state. It sends one mutation request, then reloads authoritative data. If a dispatched request has an ambiguous outcome, the UI requires a fresh read before another attempt; it does not automatically retry or report success. Verify these interruption and permission-change cases during browser acceptance.

Validate keyboard navigation, screen reader labels, responsive layout, 401/403/503 clearing, cancellation and unknown/unseen/stale/revoked/degraded states. Verify that `/lab/` and `/api/` are rejected by the secure listener. The `/lab/` React companion is available only on an explicitly separate loopback development server and must not be presented as native protected IPC.

## 8. Actual acceptance and rollback

Run `scripts/test-integrated-candidate.sh` only against a newly created `edr_integrated_test` database on `127.0.0.1:5432`, with `EDR_QA_DISPOSABLE_DB=yes`, `EDR_TEST_DATABASE_URL` and the built frontend. The harness refuses other database names/targets and existing EDR tables. It validates real Go/PostgreSQL/Rust transport and React assets, strict TLS/tenant/origin denials, degraded scanner state, explicit error results, synthetic result-to-alert plumbing and persisted revocation. Its synthetic result is not a real ClamAV detection.

Before acceptance, independently collect actual Windows Server 2022 and Ubuntu host OS/build and binary hashes; verify PKI/ACL/firewall state; run benign/EICAR-only scanner tests with verified signature databases; capture genuine Sysmon Event 7 provider/channel/record identity and demonstrate FileCreate alone is not a DLL load; exercise service restart, offline recovery, UI auth and resource limits. Never attach private keys, passwords, full lease tokens or unrelated host telemetry. A container check does not replace those deployment-host records.

Rollback must be rehearsed on the approved hosts. Keep a verified previous package and a tested database backup/restore plan. Stop the candidate, atomically switch the complete binary+UI release directory to the previous verified version, restart, and validate authenticated health and stored data. Record the previous/new manifest hashes, service state, health evidence and operator decision. Do not blindly apply reverse SQL migrations or assume an old binary supports a newer schema.

`scripts/release/linux_service.py` applies the tested POSIX switching primitive to versioned systemd installations and rechecks authenticated health after restoration. Its filesystem/service-manager fixture tests do not prove native systemd or Windows Service rollback. Native service and database-restore rehearsal remain required. If rollback health fails, retain the failure record and stop rollout.

## 9. Approval record

The deployment request must identify the exact commit and signed archive hash, successful CI run links, independent InfoSec and QA verdicts, both host acceptance records, verified publisher identity, successful rollback evidence, canary targets and deployment window. The owner must explicitly approve that concrete request. No document, automation schedule or package verification grants deployment authorization by itself.
