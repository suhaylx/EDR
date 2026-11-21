# TuranSec EDR — milestone 0.1 laboratory starter

**Status: runnable local API/dashboard prototype, not a functioning EDR or production-ready endpoint agent.**

Current parts:
- `backend/`: Go standard-library HTTP API and in-memory store for agent check-in, events, policy records, desired policy assignment, acknowledgements and overview.
- `backend/web/`: lightweight no-build dashboard served by Go. This initial smoke-test UI is **plain JavaScript**, not yet the planned React/TypeScript enterprise frontend.
- `agent/`: Rust std-only scaffold demonstrating separation of a collector worker from the core, with **no real Sysmon, ClamAV, installation or remediation logic**.
- `config/sysmon/`: **nonproduction templates** to review/validate on Windows and Linux lab VMs; never roll out as-is to enterprise endpoints.
- `scripts/replay.sh`: enroll a fake Windows lab endpoint and send one synthetic Sysmon event for UI smoke testing.
- `docs/architecture.md`: architecture and next milestones.

## Requirements

Go 1.23+, optional Rust/Cargo if you want to compile the agent stub. No external Go modules.

## Run locally

```bash
cd backend
export EDR_DEV_TOKEN="$(openssl rand -hex 32)"
export EDR_ADDR=127.0.0.1:8080
go test ./...
go run ./cmd/server
```

Browse to http://127.0.0.1:8080 and paste the token from the *same terminal's environment* into the development UI. Token remains in the browser tab's JS memory; do not use this shared-token authentication in production.

In another shell, using the **same** EDR_DEV_TOKEN:

```bash
./scripts/replay.sh
```

When in the project root, adjust the first `cd` above accordingly. E.g., `cd turansec-edr/backend` and run `../scripts/replay.sh` from backend (script works from any current directory).

## Important limitations / risk gates

- Go API is bound to localhost by default; a shared bearer token is suitable only for an isolated lab. **Do not expose port 8080 publicly.** No mTLS, per-device identity, tenant isolation, RBAC, SSO or production audit yet.
- Records are in memory and disappear at restart. No persistence, queuing, event deduplication, or accurate incident correlation yet.
- Policy creation only checks basic XML shape, **not actual Sysmon event schema**. An assignment sets a desired record in the server; it does **not** install Sysmon, change its configuration or control endpoints.
- Current Rust agent is a skeleton and does not reach this API. It does not collect events, scan files or deploy itself.
- No Active Directory connectivity, LDAPS bind, GPO creation or remote MSI installation; these are future explicitly gated features.
- Repository contains no real passwords or tokens. Never commit personal credentials.

## Planned milestones

1. Identity and security: tenant-scoped persistent database, per-agent mTLS enrollment, RBAC, immutable configuration revisions, audit.
2. Rust Windows Event Log/Sysmon reader; Linux journald parser and event coverage metadata; backend versioned schema.
3. ClamAV signature engine integration and TuranSec static PE/DLL analyzer with safety limits.
4. Agent-side isolated Sysmon policy worker: verify/backup/stage/apply/check/rollback without interrupting agent heartbeat or scanning. Canary deployment and per-agent desired/applied state.
5. React + TypeScript SOC dashboard, threat hunting, incident process tree.
6. AD/LDAPS directory discovery and read-only OU/computer targeting; signed Windows MSI and AD-admin-approved GPO deployment plans. Live execution gated on dedicated lab validation and credentials with least privilege.

## Four-role review and delivery ownership

- Security: shared dev token is intentionally not production authentication. Dynamic analysis is off-endpoint and isolated. Quarantine/delete is unimplemented. Do not use this build on production hosts.
- Developer: API and UI run without registry dependencies, stable event fields are minimal, future migration must preserve evidence provenance and process/parent GUIDs.
- QA: verify tests, forbidden XML constructs, policy precedence, invalid auth, and an event replay against Go API. Real Windows/Linux Sysmon and agent reliability testing is still outstanding.
- PM (Agent 4): maintains the prioritized backlog, delivery evidence, documentation, daily role assignments, release risks and blockers. A report or task does not imply independent background coding or a GitHub push.

## Project management documents

- [`docs/PM_MANUAL.md`](docs/PM_MANUAL.md): PM authority, four-role ownership, daily operating loop, release gates.
- [`docs/PRIORITY_BACKLOG.md`](docs/PRIORITY_BACKLOG.md): ordered P0/P1/P2 work, owners, dependencies and acceptance checks.
- [`docs/DAILY_REPORT_TEMPLATE.md`](docs/DAILY_REPORT_TEMPLATE.md): evidence-based four-role daily report.
- [`.github/workflows/ci.yml`](.github/workflows/ci.yml): proposed PR checks for Go and Rust scaffold. Requires a GitHub repository to execute.
- [`docs/LAB_PROVISIONING.md`](docs/LAB_PROVISIONING.md): isolated development server specifications, networking and owner provisioning checklist.
- [`docs/ROLE_KICKOFF_2026-11-21.md`](docs/ROLE_KICKOFF_2026-11-21.md): verified initial four-role review, P0 assignments and blockers.

GitHub publishing is separate from this local starter. Never push this project into an unrelated repository; only use the authorized private project repository once created.
