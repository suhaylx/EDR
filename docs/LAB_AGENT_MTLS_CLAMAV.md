# TuranSec EDR mTLS one-shot lab worker

**Status:** staged, draft-only; no production service, no host deployment, no
independent endpoint malware test. Required gate: Linux + Windows Rust CI,
PostgreSQL migration chain and Agent 1/Agent 3 sign-off.

## Protocol and trust

The Rust agent uses only HTTPS TLS 1.3 with its enrolled client certificate,
specified tenant/device route and an explicitly configured private CA. It
refuses HTTP, URL credentials, redirects, system proxy settings and system trust
roots. It never sends `EDR_DEV_TOKEN` or prints lease capabilities.

The backend's new `complete-result` endpoint atomically consumes a
nonexpired scan lease and persists one `edr_scan_job_results` row. This must be
deployed with migration `0008_scan_job_results.up.sql`. The old boolean
`complete` endpoint does **not** store malware evidence and MUST NOT be used
for malware workflows.

## Offline deployment prerequisites (authorized isolated lab only)

Supply secure device-local files and configuration, using the operator's
standard secret storage. **No example keys/tokens are embedded.**

| Variable | Purpose |
|---|---|
| `TURANSEC_MTLS_ORIGIN` | Bare HTTPS origin with backend DNS/IP matching server certificate |
| `TURANSEC_MTLS_TENANT_ID` | Enrolled tenant route; must match certificate SAN |
| `TURANSEC_MTLS_AGENT_ID` | Enrolled device route; must match certificate SAN |
| `TURANSEC_MTLS_CA_PEM` | Pinned organization CA PEM |
| `TURANSEC_MTLS_CERT_PEM` | Device client certificate PEM chain |
| `TURANSEC_MTLS_KEY_PEM` | Device private key PEM; Unix permissions 0600 |
| `TURANSEC_LAB_SCAN_ROOT` | Administrator-controlled, non-root scan directory |
| `TURANSEC_CLAMD_SOCKET` | Optional Unix-local clamd socket on Linux |

Windows lab clamd must bind **127.0.0.1:3310 only** and its private key must
have restrictive Windows ACLs. Windows ACL protection is currently a manual
preflight, not verified by the Rust loader. The CA/identity must be installed
via a separate approved enrollment procedure, which this PR does not implement.

Run `cargo test --manifest-path agent/Cargo.toml --all-targets`, then only
after explicit lab authorization `cargo run --manifest-path agent/Cargo.toml
-- --scan-once-mtls`. The command claims at most one job, keeps its lease
renewed during a local ClamAV scan and submits the **actual verdict** through
the authenticated result endpoint.

## Safety and failure behavior

Only a single bounded (128 MiB) regular file, inside a configured canonical
root, is permitted. Missing clamd, unsupported directory/quick/full scan,
bad paths, invalid signature names and socket errors record `error`, **never
clean**. A malware match is recorded as `malicious`, not automatically
deleted/quarantined. A failed lease renewal or result submission aborts:
the client does not fabricate success.

Canonical-path checks with a Unix inode recheck are a lab safeguard, **not**
a fully race-free `openat2`-style sandbox against an attacker who can modify
ancestor directory trees. Do not run this worker on untrusted writable trees.

## Release blockers

- Dedicated TLS listener + issuer CA are not proven deployed.
- Full real mTLS + PostgreSQL + ClamAV 1.5.5 Windows/Linux E2E verification not run.
- Rust dependency lockfile and supply-chain audit pending.
- Secure Windows key ACL/DPAPI integration and enrollment key rotation pending.
- Binary signing, service management, telemetry ingestion and signed policy pending.
- SOC alert generation/incident linking from saved results pending.
- InfoSec Agent 1 / QA Agent 3 approval required before merging or canary.
