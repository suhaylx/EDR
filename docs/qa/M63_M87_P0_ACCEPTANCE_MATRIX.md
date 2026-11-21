# TuranSec EDR — M63–M87 release-acceptance evidence matrix

**Created:** 21 November 2026, Asia/Tashkent. **Purpose:** independent Agent 3 QA must fill *observed* results. This is **NOT** evidence that any host checks were executed. See [25-milestone board](../SPRINT_M63_M87_20261121.md).

Use statuses `PASS`, `FAIL`, `BLOCKED`, or `NOT RUN`; never mark PASS from source code or CI alone. Record exact PR head SHA, GitHub Action URL, OS/kernel/build, certificate issuer fingerprint (not private keys), source event ID, UTC timestamp, log URL and reviewer for each case.

## P0 CI and security regression gates

| Case | Expected behavior | Evidence needed | Status |
| --- | --- | --- | --- |
| TLS-01 | Agent listener accepts 127.0.0.1:9443 and [::1]:9443 only with valid CA, database and keypair | New PR #129 Go positive tests plus real HTTPS handshake | NOT RUN on real host |
| TLS-02 | Reject 0.0.0.0, [::], nonloopback IPv4/IPv6, DNS host, empty/bad TCP port | Go tests on Linux race/Windows, full server startup denial | NOT RUN on real host |
| TLS-03 | Empty/nil CA, server key missing, certificate lacking client trust fail closed | Unit tests + live startup denial (no secrets logged) | NOT RUN on real host |
| TLS-04 | Reject TLS 1.2, missing client cert, unknown CA, wrong SAN, revoked/expired/future cert | Real TLS 1.3 handshake and registry negative tests | NOT RUN |
| AUTH-01 | Untrusted tenant/agent/forwarded-client-cert/Authorization headers stripped after verified mTLS; source request unchanged | New #129 regression + actual backend handler log proof | NOT RUN on real host |
| AUTH-02 | Device certificate SAN and enrolled fingerprint determine principal; client request cannot override scope | Go negative wrong device/tenant and certificate rotation | NOT RUN |
| SQL-01 | Claim and revocation serialize; no new lease after revocation commit | Two PostgreSQL sessions, migration chain, recorded SQL transaction order | NOT RUN on real host |
| SQL-02 | Stale/expired/revoked/other-tenant lease cannot renew or complete-result | Actual PostgreSQL queue tests and server restart | NOT RUN on real host |
| SQL-03 | One immutable source-backed verdict; no boolean success to clean | PG persistent row and Go API tests, duplicate result denied | NOT RUN on real host |
| RUST-01 | Bounded client PEM; Unix opened inode matches original and mode 0600; Windows ACL preflight | Ubuntu/Windows cargo CI and operator-owned Win2022 ACL tests | NOT RUN on real host |
| AV-01 | Genuine local ClamAV INSTREAM reports EICAR as MALICIOUS (never as file execution evidence) | Authorized isolated lab, clamd engine+DB version and file hash | NOT RUN |
| AV-02 | Daemon stopped/timed out, oversized file, unsafe path -> ERROR or UNSCANNED, never CLEAN | Actual agent logs with no lease secrets | NOT RUN |
| SYSMON-01 | EID1/7/11/29 source EventRecordID present; EID11 file creation never proves DLL load | Windows Server 2022 controlled test and Sysmon policy state | NOT RUN |
| TELEMETRY-01 | Offline/restart/dedupe/out-of-order/tenant denial preserve source IDs | End-to-end Windows + Ubuntu + PostgreSQL retention tests | NOT RUN |
| UX-01 | SOC distinguishes queued vs completed scan and UNKNOWN/no Sysmon instrumentation | Authenticated React tests, real browser 401/403/503, keyboard and zoom screenshots | NOT RUN on real host |
| RELEASE-01 | Signed Windows/Linux binary, backup, canary and rollback with owner/InfoSec/QA approval | Artifact checksum/signature, real install/uninstall, reviewer links | NOT RUN |

## Reproducible no-secret CI commands

```sh
cd backend
go test -race -count=1 ./...
go vet ./...
cd ../agent
cargo test --all-targets
cargo check --all-targets
cd ../frontend
npm test
npm run build
```

Run only commands supported by the corresponding checked-out branch. `npm test` may not be configured in all lab UI branches. Disposable PostgreSQL tests require an isolated database and operator-controlled connection settings; never reuse production credentials. Do not copy secrets or security-sensitive scan paths into GitHub issue bodies. EICAR and Sysmon host tests require an authorized isolated environment.

## Go/no-go

**NO-GO** until runnable Go/PostgreSQL listener is verified with a real CA and device certificate; two independent InfoSec+QA approvals; genuine Windows/Linux clamd+Sysmon telemetry; signed canary/rollback; explicit deployment owner authorization. Do not auto-merge or install endpoints. Neither a roadmap nor green CI alone clears this gate.
