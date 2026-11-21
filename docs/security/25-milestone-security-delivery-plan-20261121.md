# TuranSec EDR — 25 security milestones and acceptance gates

**Planning baseline:** 21 November 2026, Asia/Tashkent. **Scope:** reviewable laboratory implementation and the remaining production-readiness program. The product is **NOT production-ready**. This is a proposed priority/owner breakdown for PM approval, not a declaration that Agent 2/3/5 have executed their tasks. The five code milestones listed first are not merged.

**Status vocabulary:** `DRAFT / CI PASS` = code and synthetic tests committed to a draft PR; it is **not QA accepted** or deployed. `DRAFT / CI PENDING` = code committed; latest CI not yet confirmed. `PLANNED` = not implemented or verified. Every acceptance gate below must be backed by actual code, issue/PR, CI and independent QA on target systems before marking accepted.

| # | Priority | Proposed owner | Milestone and acceptance gate | Evidence | Status |
|---|---|---|---|---|---|
| 01 | P1 | Agent 1 | Windows Sysmon 12–14 Registry Run/RunOnce: EID13 mandatory, EID12/14 optional, wrong-boot/false-positive tests | [Draft PR #85](https://github.com/suhaylx/EDR/pull/85) | DRAFT / CI PASS |
| 02 | P1 | Agent 1 | WMI EIDs 19/20/21: exact names, same reported boot/device, no partial-chain alert, privacy-minimized fields | [Draft PR #93](https://github.com/suhaylx/EDR/pull/93) | DRAFT / CI PASS |
| 03 | P1 | Agent 1 | EID25 image replacement plus independently reported EID1 process creation; unverified evidence not auto-remediated | [Draft PR #99](https://github.com/suhaylx/EDR/pull/99) | DRAFT / CI PASS |
| 04 | P1 | Agent 1 | EID15 named NTFS stream detection; suppress benign Zone.Identifier and reject malformed/missing source evidence | [Draft PR #102](https://github.com/suhaylx/EDR/pull/102) | DRAFT / CI PASS |
| 05 | P1 | Agent 1 | EID11 file creation + EID29 executable-file detection; no inference of execution; false-positive tests | [Draft PR #108](https://github.com/suhaylx/EDR/pull/108) | DRAFT / CI PENDING |
| 06 | P0 | Agent 2 + Agent 1 review | Device mTLS enrollment: unique cert+device IDs, verified chain and tenant binding, wrong-device negative tests | Issue #2; SEC-001 | PLANNED |
| 07 | P0 | Agent 2 + Agent 3 | Tenant isolation/RBAC for agent, events, policy, incidents, scans and response; every cross-tenant access denied in tests | BE-001 | PLANNED |
| 08 | P0 | Agent 2 + Agent 3 | CA/cert lifecycle, bootstrap authentication, renewal/revocation/expiry and compromise recovery; deny revoked cert | BE-001 | PLANNED |
| 09 | P0 | Agent 2 + Agent 1 | Signed scoped commands with UTC expiry/nonce, anti-replay, one-device authorization and immutable audit; replay rejected | SEC-001, BE-001 | PLANNED |
| 10 | P0 | Agent 2 + Agent 3 | Signed desired/applied policy and rollback: store device policy revision, reject mismatched signatures and expired policy | SEC-001, SYS-002 | PLANNED |
| 11 | P0 | Agent 2 | PostgreSQL durable events, scan leases and response audit, schema migrations, restart integrity and backup/restore tests | BE-002 | PLANNED |
| 12 | P0 | Agent 2 | Bounded encrypted endpoint offline queue: loss-aware retry, backpressure, restart replay and no duplicate accepted evidence | AG-001, BE-002 | PLANNED |
| 13 | P0 | Agent 2 + Agent 3 | Verified event ingestion idempotency: tenant+device+boot+channel+source record scoping, stable server receipt, replay tests | SYS-003, BE-002 | PLANNED |
| 14 | P1 | Agent 2 + Agent 3 | Real Windows Sysmon collector for EIDs 1/3/7/8/10/11/12–15/17–22/25/29, capability/version gating and bookmark recovery | Issue #12 | PLANNED |
| 15 | P1 | Agent 2 | Staged Sysmon policy apply/rollback: signed config, canary, elevated EID3/7/10 volume budgets, worker isolation | SYS-002 | PLANNED |
| 16 | P1 | Agent 1 + Agent 2 | Remaining original named-pipe EID17/18, driver EID6 and Linux capability-specific detection design, benign fixtures | SYS-003 | PLANNED |
| 17 | P0 | Agent 2 + Agent 5 | Real sensor quality/coverage: per-EID present/missing/loss, sender-vs-receipt timestamp, heartbeat age, uninstrumented != healthy | SOC-001 | PLANNED |
| 18 | P0 | Agents 1+2+3 | Authentic ClamAV 1.5.5 signatures: integrity/freshness, real EICAR/benign/daemon-down test evidence, no stub-success claim | Issue #17, AV-001 | PLANNED |
| 19 | P1 | Agent 2 + Agent 3 | Quick/full/path/scheduled scans with capability negotiation, progress/cancel/timeouts/engine DB state and bounded resource cost | AV-001, AV-002 | PLANNED |
| 20 | P0 | Agent 2 + Agent 3 | Windows reparse/junction-safe handle-relative path opens; Linux openat2 QA, no cross-root or swapped-path scanning | [Draft PR #48](https://github.com/suhaylx/EDR/pull/48) (Linux only) | PLANNED |
| 21 | P1 | Agent 2 + Agent 1 | Reversible quarantine, hash-checked restore, policy/identity authorization and immutable response ledger; no default deletion | IR-001 | PLANNED |
| 22 | P1 | Agent 2 + Agent 3 | Realistic local tamper-control and signed temporary maintenance: service-stop/uninstall tests and emergency recovery | TAMPER-001 | PLANNED |
| 23 | P1 | Agents 1+2 | Static PE/DLL/ELF inspection and signer/hash/entropy metadata with fuzzed malformed files and no sample execution | DFIR-001 | PLANNED |
| 24 | P1 | Agent 5 + Agents 1/2 | SOC security posture and incident evidence graph: observed/inferred edges, missing coverage, actual alerts and scan failures | SOC-001, IR-001 | PLANNED |
| 25 | P0 | Agent 3 + PM | Release acceptance: real Windows Server 2022/Windows 11/Linux QA, race/fuzz/performance, CI green, signed builds, rollback, InfoSec sign-off | QA-001 + release checklist | PLANNED |

## Review/dependency chain and priorities

The first five increments are original **laboratory detectors only**. Their PRs stack on previous draft branches: #108 -> #102 -> #99 -> #93 -> #85 -> #63 -> #60 -> #29 -> MVP #5. CI passing only verifies configured Go/Rust test jobs, not any production sensor or EDR efficacy. Do **not** merge individual stacked PRs out of dependency order; Agent 2 and PM must review and reconcile branch ancestry and overlapping changes before integration.

The **P0 program (#06–13, #17–18, #20, #25)** must take precedence over additional heuristic rules. In particular, no product claim of live EDR or automatic prevention is supportable without actual Windows/Linux collectors, tenant-scoped device identity, durable/auditable telemetry, real ClamAV signatures, and independent QA.

## Mandatory status reporting

For each milestone, PM/assignee records (a) issue and branch/PR/commit; (b) unit/integration target and pass/fail/not-run; (c) OS, sensor, ClamAV/DB versions and timestamps when applicable; (d) safety/privacy/false-positive evidence; (e) QA and InfoSec acceptance; (f) release or rollback decision. **Not instrumented, not run and blocked must never be reported as pass.** No live endpoint tests or deployments occurred as part of this tracker.
