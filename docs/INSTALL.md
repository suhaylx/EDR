# TuranSec EDR — Installation and verification manual

> **Status (2026-11-22): PRE-PRODUCTION / LAB ONLY.** This is a source-build and validation guide, **not** a supported production installer. The `main` branch currently contains planning documentation, **not** the runnable Go/Rust/React application. Application code cited below lives on **draft, unmerged** PR branches. No CI pass, host installation, security approval, or release authorization is implied by these instructions.

## 1. Choose a source and scope

- Canonical private repository: https://github.com/suhaylx/EDR
- Backend/Rust combined QA-fix draft: [PR #159](https://github.com/suhaylx/EDR/pull/159), branch `fix/agent2-qa-review-and-security-20261121` (stacked on [PR #152](https://github.com/suhaylx/EDR/pull/152)).
- React SOC lab review draft: [PR #158](https://github.com/suhaylx/EDR/pull/158), branch `fix/agent5-backend-qa-review-20261121` (stacked on an earlier frontend draft).
- These are **different unmerged branches**. Do not assume the React frontend works against the secure mTLS SOC API from PR #159. The React UI still uses a **loopback-only development bearer token** and a separate lab Go API.
- Pin the exact commit for every run: `git rev-parse HEAD`. Verify that the source tree contains the files and commands in this manual before running anything.

## 2. Lab prerequisites

Use isolated disposable VMs or a test network, never production endpoints. Suggested *lab sizing only*: Ubuntu 24.04 LTS development host (8 vCPU, 16 GB RAM, 200 GB SSD) and Windows 11 test VM (4 vCPU, 8 GB RAM, 80 GB SSD). These are planning estimates, not validated hardware minimums.

Install through your organization's approved package channel:

- Git, Go **1.23+** for the backend module (`backend/go.mod` on PR #159), Rust toolchain with Cargo for the single Rust agent, Node.js **22+** and npm for the React slice, and PostgreSQL 16 for **disposable database tests**.
- A current C/C++ toolchain, CA certificates and OS build prerequisites as required by your actual target; do not assume platform support until tested.
- On a Windows host, use a purpose-built approved lab for Sysmon and ClamAV validation. Do not enable real-time prevention, forced isolation, remote install or quarantine against live systems.
- Keep inbound ports closed. Bind the legacy Go lab UI and React development server to **127.0.0.1** only. Use temporary lab credentials and do not paste tokens, database passwords, keys or certificate private material into commits, logs or issues.

## 3. Check out a fixed snapshot

```bash
git clone https://github.com/suhaylx/EDR.git
cd EDR
git fetch origin
# Select ONE review snapshot for each isolated test; do not silently combine them.
git switch --detach origin/fix/agent2-qa-review-and-security-20261121
git rev-parse HEAD
test -f backend/go.mod && test -f agent/Cargo.toml
```

For the React slice, use a **separate worktree** or checkout and capture its SHA:

```bash
git worktree add --detach ../EDR-frontend origin/fix/agent5-backend-qa-review-20261121
cd ../EDR-frontend
git rev-parse HEAD
test -f frontend/package.json
```

Branches may change; recorded SHA, not a moving branch name, is the reproducible evidence. A draft branch is not an approved release artifact.

## 4. Backend source checks (PR #159 snapshot)

```bash
cd backend
go mod download
go test -count=1 ./...
go test -race -count=1 ./...  # Linux/macOS with supported race toolchain
go vet ./...
```

Record exit codes, test output, OS, Go version and commit SHA. These commands **build/test packages**; they do **not** prove a deployed authenticated Go/PostgreSQL mTLS service or install a daemon. Do not invent a server start command or assume an mTLS listener is enabled by default. Consult reviewed listener/configuration documentation and validate TLS 1.3, client CA trust, certificate revocation, tenant identity and fail-closed behavior before any network exposure.

## 5. Single Rust endpoint agent source checks (PR #159 snapshot)

```bash
cd agent
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked
```

If a lockfile is missing on the selected snapshot, stop and resolve that reproducibility issue rather than silently replacing a pinned build. Run Windows and Linux host tests **independently** on approved VMs. A compiled binary is not proof that Sysmon, ClamAV supervision, device enrollment, heartbeats or policy application works.

## 6. Disposable PostgreSQL tests (PR #159 snapshot)

**DANGER: the following SQL suites are for a fresh, explicitly disposable database only.** Do not point them at a production, shared, or pre-existing database. Use a dedicated, limited-privilege PostgreSQL 16 test role and record the database and test-run identity without logging its password.

From the repository root, check scripts and migrations in the selected snapshot before execution:

```bash
ls backend/migrations
ls scripts/test-*.sh
export EDR_TEST_DATABASE_URL='postgresql://<test-user>:<password>@127.0.0.1:5432/<fresh-test-db>?sslmode=disable'
# Replace placeholders locally; do not commit or paste this value into artifacts.
bash scripts/test-enrollment-challenges.sh
```

The enrollment challenge script applies specific migrations to its disposable database and tests valid claim, wrong tenant/device/digest, expiry, disabled tenant and replay; do **not** run overlapping stateful suites against the same dirty database. For certificate rotation, tenant-disablement concurrency, challenge restart and full migration chain, use their reviewed workflow/scripts, each with a **fresh** database and required explicit disposable-db safeguards. Capture script name, migration chain, SHA, exit result and PostgreSQL version. This manual does not assert those suites have passed.

## 7. React SOC lab UI (PR #158 snapshot)

On the **frontend branch worktree**:

```bash
cd frontend
npm ci
npm run typecheck
npm test
npm run build
npm run dev
```

The draft frontend README describes Vite at `127.0.0.1:5173` proxying `/api` to the **separately running legacy Go lab server** at `127.0.0.1:8080`. The Go lab server must be started with the reviewed lab-specific instructions and a temporary `EDR_DEV_TOKEN`; no validated universal launch command is supplied here. Enter the lab token directly in the UI, **not** in a Vite environment variable. This is a shared-token lab design, **not** mTLS SOC operator authentication or tenant-safe RBAC.

The frontend is read-only; verify loading/empty/error/unknown status, keyboard focus, contrast, screen reader behavior, authorization failures, and that endpoint-supplied error strings or raw policy XML are not displayed. Its metadata endpoint `GET /api/policy-metadata` is part of the lab integration on PR #158, not a production authorization guarantee. Do not point this Vite UI at a live SOC or production tenant.

## 8. Security and host acceptance gates — not installation claims

Before considering an integrated candidate, require *independent, exact-head* evidence for:

1. Agent 1 InfoSec review/approval of device/operator trust boundaries, mTLS CA separation, tenant scope, replay/revocation, detection trust and safe response behavior.
2. Agent 2 executable Go service with PostgreSQL migrations/driver and mTLS certificate-enforced requests, integrated with the **one** Rust endpoint agent; passing Go, Rust, SQL and negative-auth tests at the actual candidate SHA.
3. Agent 3 QA independent exact-head CI, disposable PostgreSQL restart/rotation-race tests, genuine Windows and Linux agent/service host acceptance, approved safe ClamAV EICAR and Sysmon event 1/7/11 checks (event 11 file creation is **not** event 7 module load), explicit verdict and reproducible evidence.
4. Agent 5 original React SOC/local companion integration, passing TS/build/tests, browser keyboard/accessibility, auth denial and honest unknown/offline-state evidence against the approved API contract.

Record per gate: PR URL, **full commit SHA**, workflow/job link with executed steps and passing result, manual host evidence with OS/tool versions, reviewer and verdict. An empty-step failed Actions run, unrelated green parent commit, draft PR or “done” comment does not satisfy the gate.

## 9. Deployment authorization and rollback

**NO-GO by default.** Do not merge, publish installers, open inbound ports, enroll real devices, execute remote response or deploy based on this manual. Any future production rollout needs explicit owner approval, InfoSec approval, independent QA PASS, verified package/signature, tested least-privilege installation, canary criteria, rollback, audit trail and emergency stop. No production readiness is claimed.

For current blockers see [CI runner issue #153](https://github.com/suhaylx/EDR/issues/153), [QA acceptance #154](https://github.com/suhaylx/EDR/issues/154), and [security review #155](https://github.com/suhaylx/EDR/issues/155).
