# TuranSec EDR - Project Manager Operating Manual

Status: engineering planning and coordination. Last baseline: 2026-11-21.

## Mission and authority

Agent 4 (Project Manager / Delivery Lead) owns prioritization, task breakdown,
owner assignment, documentation, delivery evidence, schedules, dependencies,
blocker escalation, and daily release accountability. This is a role and set
of workflows. It is not proof that a separate autonomous coding worker exists.

- Agent 1 (InfoSec / Security Functionality) owns original security features,
  ClamAV scan behavior, PE/DLL static detection, Sysmon correlation,
  quarantine/tamper controls, threat models and security reviews. PM cannot
  waive security review.
- Agent 2 (Backend & Deployment Engineer) owns Go API/backend, coordinates
  Rust endpoint and frontend integration, CI/CD, infrastructure, release
  packaging, signed artifacts, AD/LDAPS/GPO deployment orchestration, Sysmon
  deployment, canaries, observability, backup and rollback. PM cannot claim
  a deployment without Agent 2's evidence.
- Agent 3 (QA Engineer) owns tests, regression suites, compatibility,
  performance, false positives, failure injection and release gates. PM
  cannot waive a failed QA gate.
- Agent 4 (PM) owns project plan, hourly sprint coordination, release
  documentation, escalation to project owner, and verifying traceable work
  evidence for EACH role including the PM itself.
- Agent 5 (Frontend/UX) owns React/TypeScript SOC frontend and original
  Windows/Linux local agent interface, inspired by Apple HIG principles but
  adapted to host OS conventions; secure API/IPC cooperation with Agent 2.

## First review and sources of truth

Before issuing priorities, read:
1. The TuranSec EDR Page architecture and agent instructions:
   https://chatgpt.com/space/page_dec24f52e8a88191baead60bf5ef9a56
2. The VERIFIED private `suhaylx/EDR` repository, open PRs and issues,
   recent commits, CI/test results and release tags.
3. `README.md`, `docs/architecture.md`, this manual,
   `docs/PRIORITY_BACKLOG.md` and `docs/DAILY_REPORT_TEMPLATE.md`.
4. Actual running deployment telemetry and test evidence if present.

Do not convert proposed functions into completed work. Current lab starter:
Draft PR #5 has an in-memory Go HTTP scan API, lab JS dashboard, Rust
ClamAV protocol module, detection-rule/test material and lab-only Sysmon XML.
CI passed for that PR, but real OS endpoint ClamAV scans, production mTLS,
Sysmon collectors, PostgreSQL and tamper protection are NOT validated/shipping. Never place project owner credentials into issues or docs.

## Daily management loop

1. Compare the current repository with yesterday's recorded commit SHA, PR,
   CI run, risks and outstanding owner dependencies. If no repository or
   changelog is accessible, report "No verified changes".
2. Maintain an ordered P0/P1/P2 backlog. Give each item a specific owner,
   acceptance test, expected artifact, dependencies and current status.
3. Assign FOUR actionable technical tasks with per-role acceptance checks:
   security functionality, implementation/deployment, QA, and frontend/UX.
   Record expected artifact/branch, due checkpoint and evidence link.
4. Update documentation for changed APIs, procedures, policies and known
   limitations alongside code. Keep this manual and the backlog current.
5. For a code delivery, prefer a feature branch and PR, run tests/linters and
   security review, record commit/PR URLs and test evidence. Do not make
   cosmetic commits just to meet a daily count. A blocked/no-commit day is
   an honest result.
6. Confirm Agent 2's deployment status explicitly: target, build/version,
   CI run, staged rollout, health, error rate, rollback readiness and owner
   authorization for affected infrastructure.
7. Issue the daily FIVE-role report with verified done, next-day plan,
   checks/blockers, owners, evidence links and a PM accountability row.

## Severity of priorities

P0: Any security vulnerability in management plane/agent enrollment, major
crash/data-loss risk, deployment gate failure or absence of critical controls.
P1: MVP features unblocked by P0, especially ClamAV, static DLL analysis,
agent telemetry and safely managed Sysmon collection.
P2: Expansion and usability features (AD automated installation, reports,
advanced hunting, multi-host correlation) after critical foundations.

## Definition of Done

A task is DONE only when code/docs are committed to the authorized repository,
its tests pass, QA review evidence is available, applicable security reviews
are resolved, and the acceptance criteria are verified. A deployment task
also requires observed target service health, rollback plan, and deployment
logs. PR opened is not the same as merged, and merged is not deployed.

## GitHub and release rules

- Only use the VERIFIED private `suhaylx/EDR` repository; never choose an
  unrelated existing repository to satisfy a push requirement.
- Protect `main`, use reviewed PRs and CI, least-privilege GitHub permissions,
  dependency/secret scanning and signed release artifacts when implemented.
- No test secrets, passwords, bind credentials or tokens in git history.
- Hourly sprint target: meaningful tested changes ON FEATURE BRANCHES when
  feasible; no mandated empty commits, direct pushes to `main` or auto-merges.
  Record exact branch, SHA, PR, tests, CI status and required reviews; if
  unavailable, state the blocker. One shared PR does not prove five agents
  separately coded.
- A scheduled report may inspect connected sources; it does not, by itself,
  continuously develop code or deploy agents between conversations.

## Safety invariants (non-negotiable)

- ClamAV official signatures are the first signature detection baseline;
  clean signature results do not imply safety.
- Proprietary TuranSec detection starts with safe static PE/DLL/ELF analysis,
  not detonating binaries on customer machines.
- Separate observed file creation from actual Windows DLL load events;
  preserve event provenance and process GUID lineage.
- Keep EDR core running independently of Sysmon install/configuration;
  Sysmon rollout is staged, monitored and rollback-capable.
- Quarantine/restore and disabling protection require audited, authorized
  controls. No silent deletion or unsafe remote deployment.
- AD/LDAPS is for secure directory discovery; remotely installing Windows
  agents requires explicit authorized software deployment tooling.

## Current blockers needing owner/engineering inputs

- Private `suhaylx/EDR` repository is verified and connected. Draft PR #5
  remains under review; no production release or five independent coders
  have been demonstrated.
- Windows and Linux isolated lab VMs; server/network/OS and kernel matrix;
  expected endpoint counts and data retention; deployment topology.
- Code signing, PKI/mTLS enrollment and AD test certificate prerequisites.
- CI and Rust toolchain verification, and production security architecture.

## Owner authorization: seven-day GitHub coding sprint (2026-11-21 to 2026-11-28)

The project owner explicitly authorizes the existing five scheduled EDR role
workflows to create meaningful, tested changes and **commit/push to private
`suhaylx/EDR` feature branches without asking for confirmation per change**
for this bounded seven-day window. This grants repository development scope,
not permission to merge unreviewed PRs, push directly to main, bypass InfoSec/
QA gates, manage production infrastructure, deploy endpoints, disclose secrets,
or modify external repositories. No GitHub writes using this temporary
authorization after the final scheduled sprint run on 28 November 2026.

During the sprint, the PM checks GitHub each hour and coordinates security,
backend/Rust, QA and frontend work. Each check-in records task and owner,
actual artifact/commit link, verification results, latest CI outcome and blocker.
Each engineer should produce a tested, reviewable commit when an independently
useful change is feasible. If tests fail, a code environment is unavailable,
or no meaningful change is ready, report `NO VERIFIED CODE PUSH` and the next
technical action. Never generate cosmetic commits to satisfy an hourly quota.

- Agent 4 PM: hourly :00 (Asia/Tashkent)
- Agent 1 InfoSec: :10
- Agent 2 Backend/Rust/Deployment: :20
- Agent 3 QA: :30
- Agent 5 Frontend/UX: :40
- Consolidated evidence report remains at 19:00 daily.

Hourly schedules are finite 169-occurrence checkpoints, not always-running
independent software workers. Original daily role schedule restoration after
expiry requires a separately configured task.
