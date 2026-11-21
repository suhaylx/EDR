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
