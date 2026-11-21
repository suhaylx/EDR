# TuranSec EDR - Project Manager Operating Manual

Status: engineering planning and coordination. Last baseline: 2026-11-21.

## Mission and authority

Agent 4 (Project Manager / Delivery Lead) owns prioritization, task breakdown,
owner assignment, documentation, delivery evidence, schedules, dependencies,
blocker escalation, and daily release accountability. This is a role and set
of workflows. It is not proof that a separate autonomous coding worker exists.

- Agent 1 (InfoSec Engineer) owns security architecture, threat detection,
  threat model, risks, telemetry integrity, and security review. PM cannot
  waive security review.
- Agent 2 (Backend & Deployment Engineer) owns Go API/backend, coordinates
  Rust endpoint and frontend integration, CI/CD, infrastructure, release
  packaging, signed artifacts, AD/LDAPS/GPO deployment orchestration, Sysmon
  deployment, canaries, observability, backup and rollback. PM cannot claim
  a deployment without Agent 2's evidence.
- Agent 3 (QA Engineer) owns tests, regression suites, compatibility,
  performance, false positives, failure injection and release gates. PM
  cannot waive a failed QA gate.
- Agent 4 (PM) owns project plan, daily coordination, release documentation,
  escalation to project owner, and verifying traceable work evidence.

## First review and sources of truth

Before issuing priorities, read:
1. The TuranSec EDR Page architecture and agent instructions:
   https://chatgpt.com/space/page_dec24f52e8a88191baead60bf5ef9a56
2. The current repository, open PRs and issues (once created and connected),
   recent commits, CI/test results and release tags.
3. `README.md`, `docs/architecture.md`, this manual,
   `docs/PRIORITY_BACKLOG.md` and `docs/DAILY_REPORT_TEMPLATE.md`.
4. Actual running deployment telemetry and test evidence if present.

Do not convert proposed functions into completed work. Current lab starter:
Go in-memory HTTP API + plain JS demo dashboard + Rust scaffold and lab-only
Sysmon XML. No live EDR agent, ClamAV, AD installer, mTLS or tamper protection
is shipping yet. Never place project owner credentials into issues or docs.

## Daily management loop

1. Compare the current repository with yesterday's recorded commit SHA, PR,
   CI run, risks and outstanding owner dependencies. If no repository or
   changelog is accessible, report "No verified changes".
2. Maintain an ordered P0/P1/P2 backlog. Give each item a specific owner,
   acceptance test, expected artifact, dependencies and current status.
3. Issue the next three actionable tasks and checks: one security, one
   implementation/deployment, one QA; align cross-role work before claiming
   a release-ready milestone.
4. Update documentation for changed APIs, procedures, policies and known
   limitations alongside code. Keep this manual and the backlog current.
5. For a code delivery, prefer a feature branch and PR, run tests/linters and
   security review, record commit/PR URLs and test evidence. Do not make
   cosmetic commits just to meet a daily count. A blocked/no-commit day is
   an honest result.
6. Confirm Agent 2's deployment status explicitly: target, build/version,
   CI run, staged rollout, health, error rate, rollback readiness and owner
   authorization for affected infrastructure.
7. Issue the daily four-role report with verified done, next-day plan,
   checks/blockers, owners and links. Escalate missing access to the owner.

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

- Only use the intended private `turansec-edr` repository; never choose an
  unrelated existing repository to satisfy a push requirement.
- Protect `main`, use reviewed PRs and CI, least-privilege GitHub permissions,
  dependency/secret scanning and signed release artifacts when implemented.
- No test secrets, passwords, bind credentials or tokens in git history.
- Daily target: meaningful reviewable change, not a mandatory main-branch
  push. Record exact branch, commit, PR and test summary; if unavailable,
  state the blocker.
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

- Intended private GitHub repository must be created/verified and connected
  before remote publishing can be claimed.
- Windows and Linux isolated lab VMs; server/network/OS and kernel matrix;
  expected endpoint counts and data retention; deployment topology.
- Code signing, PKI/mTLS enrollment and AD test certificate prerequisites.
- CI and Rust toolchain verification, and production security architecture.
