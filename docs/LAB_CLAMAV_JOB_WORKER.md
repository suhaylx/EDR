# Rust agent -> Go scan jobs -> ClamAV clamd (development-only)

**Status:** One-shot lab integration, no background endpoint service, mTLS/tenant device authentication, durable queue, signed command policy, production safe path handling, installed Sysmon collector or actual ClamAV server test evidence. Real ClamAV *requires a separate locally running, maintained clamd instance* and real virus signature database.

## Local lab setup

1. Build and start the existing Go backend on loopback: `cd backend && export EDR_DEV_TOKEN="$(openssl rand -hex 32)" && go run ./cmd/server`; record the temporary token securely. Do **not** forward port 8080 off the workstation.
2. On the **same lab host**, install/configure ClamAV separately, maintain official signatures with `freshclam` and enable local Unix socket `/run/clamav/clamd.ctl` (Linux) or loopback `127.0.0.1:3310` (Windows). Ensure the agent user has legitimate socket and scan-root permissions. Never expose unauthenticated clamd to public networks.
3. Register a lab endpoint using `POST /api/agents` and that token with `{"id":"lab01","platform":"linux"}`. Register platform corresponding to your host.
4. Put a **benign** file within an explicitly controlled test directory (e.g. `/tmp/turansec-safe-lab`), then use `POST /api/scan-jobs` with `{"agent_id":"lab01","request_id":"demo-001","scan_type":"path","path":"/tmp/turansec-safe-lab/benign.txt"}`. Use a Windows local absolute path on Windows.
5. In the **same lab host** terminal environment run:

```bash
export EDR_DEV_TOKEN=<same-temporary-token>
export TURANSEC_LAB_SCAN_ROOT=/tmp/turansec-safe-lab
# optional Linux: export TURANSEC_CLAMD_SOCKET=/run/clamav/clamd.ctl
# optional dev port: export TURANSEC_DEV_API_PORT=8080
cd agent
cargo run -- --lease-and-scan lab01
```

The worker leases **at most one job** from `POST /api/agents/lab01/scan-lease`, opens a regular file after canonical root checks, streams it to local clamd with `zINSTREAM`, and reports the scan verdict via `POST /api/scan-jobs/{job_id}/result`. View the result with `GET /api/scan-jobs` and the same temporary token. `clean_by_signature` means only a signature scan returned clean; `malicious` requires a named signature; daemon errors, inaccessible files, timeout and unsupported quick/full profiles produce error/unscanned outcomes, not fake completed protection. No files are removed, executed or quarantined.

**Important limitations:** The Go backend uses a shared development bearer token rather than verified device credentials and stores jobs in memory. The result is a **claimed lab completion**, not cryptographic scan attestation. Leases expire after 60 seconds and whole-job expiry after 30 minutes; late results fail closed. A crash between scanning and result reporting may cause re-leasing and duplicate scans. Root canonicalization is not yet race-safe against malicious filesystem namespace changes. Scan-size cap is 128 MiB. Production requires signed device-bound scope, mTLS, safe descriptor-relative opening, persistent journaled jobs, renewal/heartbeats for long scans, secure local service IPC, audit and rollout/QA on Windows and Linux. High-rate scans must use quotas and backpressure.

## QA

- `cargo test` verifies rejection of an agent-mismatched lease, malformed paths and identifiers, refusal to scan outside configured root, Unicode-safe result bounds, and honest unsupported quick/full states.
- `go test ./...` continues to validate server scan job creation, leasing and result contract.
- Run a real ClamAV EICAR safe fixture in an isolated approved lab to verify real signature detection; this is **NOT RUN** in this increment unless separately evidenced.
- Simulated stub ClamAV tests in the existing adapter do not establish installation or configured scanner health.
