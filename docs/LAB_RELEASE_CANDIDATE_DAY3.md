# TuranSec EDR — accelerated Day 1–3 laboratory candidate

**Scope:** review-only integrated lab candidate, intended for two **freshly rebuilt
authorized test VMs**: Ubuntu Server 24.04 x64 (Go SOC/backend + optional Linux
agent) and Windows Server 2022 x64 (Rust/Sysmon/ClamAV test endpoint).

**NOT A PRODUCTION EDR RELEASE.** No continuous real-time cross-OS protection,
signed deployment package, enterprise tenancy enforcement, tamper protection,
durable SOC event storage, malware removal or endpoint mTLS channel is claimed.
These features remain release blockers. Do not expose the development bearer
token over public HTTP.

## What is in this integrated source branch

- Go development SOC backend with process-evidence graph, fleet KPIs, scan jobs.
- PostgreSQL identity/certificate registry and scan lease SQL modules +
  integration tests. **This separate protected-identity path is not yet
  attached to the shared-token Go SOC listener**.
- Original React/TypeScript SOC UI and light/dark, accessible investigations;
  original Go-served lab dashboard. Both enforce localhost/HTTPS login.
- Windows portable Rust agent for *actual* Sysmon Operational Event ID 1
  observations, loopback-only Go API check-ins and 60-second polling.
- Ubuntu portable Rust agent for *actual* limited procfs process snapshots:
  source=procfs, type=process_observed, NOT a creation/exec event.
- Explicit Windows path restrictions and Linux openat2 handle-based scan
  path restrictions, with deny tests. ClamAV is a separately installed vendor
  daemon, not embedded or silently installed by this project.

## Release gates — no green check, no release label

| Gate | Required proof | Status before exact-head CI and host tests |
| ---- | -------------- | ------------------------------------------- |
| Go backend | go test ./..., go vet ./... | CI REQUIRED |
| Rust Windows x64 | Windows Server 2022 cargo test/build + EXE smoke, SHA-256 artifact | CI REQUIRED |
| Rust Ubuntu x64 | Ubuntu 24.04 cargo test/build + ELF smoke, SHA-256 artifact | CI REQUIRED |
| Frontend | TS typecheck, Node tests, Vite build; public HTTP token denial | CI REQUIRED |
| PostgreSQL | disposable database migrations, lease expiry, cross-tenant and committed-revocation denies | CI REQUIRED |
| Security review | review certificates, scan roots, shared-token limitations and sensitive data exposure | NOT SIGNED OFF |
| Windows host | real Sysmon 1, accepted heartbeat, observed lineage in SOC | NOT RUN |
| Linux host | real /proc process_observed, accepted heartbeat, no invented lineage | NOT RUN |
| ClamAV engine | isolated actual clamd / signature database, benign+EICAR-only verdict and fault tests | NOT RUN |
| Durability and recovery | real event persistence, offline spool, restart/revocation and replay | NOT IMPLEMENTED |

**Exact commit SHA** must be recorded from the successful GitHub PR #49 Actions
build when packaging. A prior green PR or a successful self-test is not valid
proof for a newer release SHA.

## 1. Ubuntu backend after OS rebuild — authorized lab only

Follow docs/LAB_UBUNTU_2404_DASHBOARD_INSTALL.md, but use the integrated
branch rather than the legacy dashboard-only branch:

~~~bash
git clone --branch integration/day2-lab-candidate-20261121 git@github.com:suhaylx/EDR.git "$HOME/turansec-edr"
cd "$HOME/turansec-edr/backend"
go test ./...
go vet ./...
go build -trimpath -o turansec-edr-api ./cmd/server
~~~

For an existing test VM, back up the currently installed web assets before
replacing files. The Go development server reads EDR_ADDR, EDR_DEV_TOKEN and
EDR_WEB_DIR. Use a generated *local* dev token that is never committed, printed
in screenshots or sent via public HTTP. For QA, favor
EDR_ADDR=127.0.0.1:8080. If binding 0.0.0.0:8080 as requested for the host,
**block all external TCP 8080 in cloud firewall and UFW** before starting it.
Keep PostgreSQL port 5432 similarly private.

The regular web dashboard ships in backend/web. To trial the independent React
SOC UI as **web assets served by the same Go backend**, install Node 22 and run:

~~~bash
cd "$HOME/turansec-edr/frontend"
npm install --no-audit --no-fund
npm run typecheck
npm test
npm run build
~~~

Then set EDR_WEB_DIR to an authorized, root-owned deployment copy of
frontend/dist instead of backend/web. **Do not copy the Vite developer server
to a public network.** The Go API remains shared-token lab-only.

## 2. Windows endpoint after OS rebuild

- Use the unsigned Windows EXE ZIP produced by the **successful**
  windows-lab-agent-build Action for the exact integrated SHA.
- Verify SHA256SUMS before execution and preserve Windows protections.
- Install the official signed Sysmon package separately, with genuine
  process-create Event ID 1 logging enabled.
- On Windows, open an SSH tunnel *from the endpoint* to Ubuntu's loopback
  API. The agent never sends its token directly to a public IP.
- Follow docs/WINDOWS_TELEMETRY_QUICKSTART.md. Start with
  --telemetry-once win-lab-01, then --telemetry-loop win-lab-01.
- Create one benign process on Windows. Verify the dashboard receives its
  actual process GUID and source Windows RecordID.
- No Windows service is installed, and no automatic remediation occurs.

## 3. Linux endpoint

Use the successful linux-lab-agent-build GitHub Actions artifact
TuranSec-EDR-Lab-Ubuntu-2404-x64, verify SHA256SUMS and follow
docs/LINUX_TELEMETRY_QUICKSTART.md. With a private local Go API or a dedicated
SSH tunnel, run:

~~~bash
./turansec-edr-agent --linux-telemetry-once linux-lab-01
./turansec-edr-agent --linux-telemetry-loop linux-lab-01
~~~

The lab agent runs unprivileged. Expect observation records, not process
creation detection or complete system coverage.

## 4. SOC acceptance and rollback

- Both enrolled endpoints are visible as lab agent records with fresh
  server-received heartbeats. Offline/unknown state must reflect received
  evidence, not an assumed agent health flag.
- Windows events: actual Sysmon source, event ID 1, image/parent GUID,
  source RecordID. Linux events: /proc process_observed without GUID.
- No alert is invented for benign activity; scan results distinguish failed,
  unscanned and scanner errors. Unsupported quick/full scans cannot be
  reported as clean or malicious.
- Endpoint actions are not performed. SOC graph retains event provenance.
- Rollback is non-destructive: stop the agent consoles and SSH tunnels,
  return EDR_WEB_DIR to the previous web asset directory and stop the Go lab
  service if needed. Existing in-memory records disappear on backend restart.
- QA must capture sanitized process output, screenshots and test case IDs
  without exposing API tokens, private keys, VNC links or host credentials.

## Security / production blockers

Before any pilot with customer data: real mTLS agent enrollment wired to the
endpoint channel, tenant-based authorization on every read/write, PostgreSQL
event storage and retention, offline durable and deduplicated telemetry,
signed installers and updates, endpoint services with least privilege,
tamper-safe maintenance, resource/DoS limits, Linux audit/eBPF provenance,
Sysmon event-loss accounting, authenticated ClamAV result attestation and
independent offensive/defensive QA.

**PM verdict:** Passing CI allows a **LAB RELEASE CANDIDATE FOR ISOLATED
TESTING ONLY**. It never implies enterprise EDR completeness, safety or
production-readiness.
