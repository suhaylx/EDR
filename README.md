# TuranSec EDR — integrated engineering candidate

**The PostgreSQL-backed mTLS service, one Rust scan client and original React SOC are integrated for engineering validation. Deployment remains NO-GO until the exact candidate passes CI, native host acceptance, independent InfoSec/QA review and signing/rollback gates.**

Read the current [installation and rollback manual](docs/INSTALLATION.md) first. It supersedes the legacy lab quickstarts for the authenticated candidate.

## Components

- `backend/cmd/edrd`: compiled Go service with TLS 1.3 client certificates, separate endpoint/operator CAs, per-request registry checks, certificate-bound mutation transactions and PostgreSQL persistence.
- `frontend`: original React/TypeScript operator SOC served on the same authenticated origin. Fleet/alert/case reads use the operator certificate. The explicit `/lab/` companion remains a separate development UI.
- `agent`: one Rust binary with authenticated heartbeat and bounded scan-job modes. ClamAV and Sysmon are separately provisioned dependencies; one-shot scan support does not establish an installed background protection service.
- `backend/cmd/server` and `backend/web`: legacy loopback, shared-token, in-memory demonstrations. These do not establish the authenticated service's detection or identity guarantees.
- `backend/bootstrap/runtime_privileges.sql`: explicit least-privilege deployment bootstrap after migrations, requiring separate registry and runtime logins.
- `.github/workflows/candidate-ci.yml`: mandatory tests on the exact PR head; no inherited-parent or scheduled-run completion.

## Build requirements

Go 1.25 or later, Rust/Cargo with the committed `Cargo.lock`, Node 22.12 or later with the committed npm lockfile, PostgreSQL 16, Python 3 and OpenSSL. The tested local toolchain versions and remaining platform limits are recorded in the candidate evidence. Never substitute a new lockfile during release staging.

## Legacy development demonstration

The commands below run the old in-memory lab server only. For the authenticated candidate use [docs/INSTALLATION.md](docs/INSTALLATION.md).

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
