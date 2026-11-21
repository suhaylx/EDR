# TuranSec EDR — Engineering Operating Manual

Status: initial engineering specification; not a production product.

## Canonical sources
- Project repository: https://github.com/suhaylx/EDR (private)
- Architecture: https://chatgpt.com/space/page_dec24f52e8a88191baead60bf5ef9a56
- Use original code and UI; vendor tools are functional references, not source to copy.

## Five accountable roles
1. **InfoSec / Security Functionality**: define and verify AV/EDR security features, ClamAV scan behavior, safe DLL/static analysis, Sysmon detection rules, quarantine/tamper controls, threat model.
2. **Backend & Deployment**: Go APIs, Rust unified agent, PostgreSQL, enrollment, CI, infrastructure, packaging, and authorized Windows/Linux deployment/rollback.
3. **QA**: security, unit, integration, Windows/Linux, non-disruption, performance and release gates.
4. **PM**: assign technical tasks with acceptance criteria to roles 1/2/3/5; verify code/tests/reviews; resolve blockers and report evidence.
5. **Frontend & UX**: React/TypeScript SOC dashboard, local Windows UI and optional Linux UI; HIG-inspired, original accessible designs and reviewed API contracts.

## Daily technical handoff
For every role: task ID, priority, exact deliverable, acceptance tests, dependency, status, evidence URL. Prioritize P0 identity/tenant isolation and CI/persistence before prevention claims. Use issues and reviewed PRs; never commit secrets, use chat-shared passwords, or push untested changes solely to claim daily activity. Report 'not verified' honestly when code/tests or deployment are inaccessible.

## Deployment policy
Agent 2 owns releases, packaging, canary and rollback. Agent 1 must approve security-sensitive behavior; Agent 3 verifies testing; PM coordinates but cannot waive security/QA gates. One TuranSec endpoint product integrates Rust + managed ClamAV and Sysmon facilities; the vendor processes/services stay isolated from the core.

## Lab minimum
Ubuntu 24.04 LTS dev server: 8 vCPU, 16 GB RAM, 200 GB SSD. Windows 11 test VM: 4 vCPU, 8 GB RAM, 80 GB SSD. Isolated networking, snapshots and test credentials; AD and dedicated ClickHouse testing later.

## Current 25-milestone sprint sources — 21 November 2026

Use [the next M13–M37 delivery board](SPRINT_NEXT_25_MILESTONES_20261121.md) after [M01–M12](SPRINT_12_MILESTONES_20261121.md). Priorities remain in [PRIORITY_BACKLOG.md](PRIORITY_BACKLOG.md); five-role proofs and checkpoints in [AGENT_ACTIVITY.md](AGENT_ACTIVITY.md). Draft PR #101 limits lab mTLS binding to loopback; it is not a deployed authenticated service. Keep Code/CI vs independent InfoSec review vs QA vs on-host deployment separate; no 25 cosmetic commits, main merges, secret reuse or unauthorized endpoint installs.


## Current implementation checkpoints: M38–M62 (21 Nov 2026)

Track [the next 25 milestones](SPRINT_M38_M62_20261121.md), following [M13–M37](SPRINT_NEXT_25_MILESTONES_20261121.md). The immediate P0 technical commit is [draft PR #117](https://github.com/suhaylx/EDR/pull/117) (Rust key inode/PEM bounded-read tests, dependent on #113), not production enrollment. The accepted evidence distinctions remain unchanged: exact SHA and CI, independent security review, independent QA, real authorized Windows/Linux validation, explicit owner-approved rollout. A 25-item plan is not 25 completed milestones. Do not merge to main automatically or treat scheduled automations as independent code execution.


## Current engineering milestone batch M63–M87 (21 November 2026)

The new authoritative [25-milestone M63–M87 board](SPRINT_M63_M87_20261121.md) follows [M38–M62](SPRINT_M38_M62_20261121.md) and earlier backlog. Exact artifact, test, dependency, owner and release gate per item; never call all 25 completed for a board update. Current shared P0 implementation is [draft PR #129](https://github.com/suhaylx/EDR/pull/129) (mTLS listener trust and loopback guard on the active scan-result stack), not a running service. [Priority backlog](PRIORITY_BACKLOG.md) and [five-role evidence](AGENT_ACTIVITY.md) retain separate code, CI, independent review, two-host lab and production statuses. No automatic merge or endpoint deployment.


## Accelerated three-day checkpoint — 21 November 2026

The user requested the entire three-day sprint be advanced immediately on Nov 21. Treat [ACCELERATED_3_DAY_SPRINT_20261121.md](ACCELERATED_3_DAY_SPRINT_20261121.md) as the evidence source: Day 1 code (listener/header trust port to latest Backend #136), Day 2 loopback TLS 1.3 + fake SQL heartbeat and revocation test, Day 3 QA matrix and **NO-GO**. Do not claim Nov 22–23 have elapsed, or that green CI on parent #136 means green CI on new [draft PR #142](https://github.com/suhaylx/EDR/pull/142). Its two latest workflows failed before runner steps appeared; exact root cause and independent code QA unknown. Real endpoint install, signer/PKI, approved Go PostgreSQL driver and live two-host tests remain blocked. No automatic main merge/deployment.
