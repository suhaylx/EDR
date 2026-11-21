# TuranSec EDR — Cross-Team QA Review and Release Gate

**Date:** 21 November 2026, Asia/Tashkent. **Reviewer:** Agent 3 (QA). **Repo:** private `suhaylx/EDR` only. **Decision:** **PRODUCTION NO-GO; QA approval withheld.**

**Review scope:** source of integrated lab [PR #49](https://github.com/suhaylx/EDR/pull/49) at `0466e7c47f098ffdb83f7818eb6571e0d941aebe`, QA [#96](https://github.com/suhaylx/EDR/pull/96) at `ce261a4bb6b86f0f51cb38add70d2f1dd490a91d`, and latest stacked backend SOC [#149](https://github.com/suhaylx/EDR/pull/149) → [#150](https://github.com/suhaylx/EDR/pull/150) → [#152](https://github.com/suhaylx/EDR/pull/152) at `a98adc46ff77474db78739f4e12b12a699a30702`. Reviewed available InfoSec specifications and frontend TypeScript. These are **distinct draft branches, not a single merged release**.

**Execution environment:** accessible GitHub private source/CI metadata only. No checked-out source tree or Rust Cargo test environment available to this QA runtime; no production server access, Windows/Linux host logs, real browser, AD controller or official clamd scanner invoked. No merge or deployment. Do not mistake source inspection for executed testing.

## Evidence ledger

| Change set / evidence | Verified status | Scope limitation |
| --- | --- | --- |
| [Lab integration PR #49](https://github.com/suhaylx/EDR/pull/49) | **PASS**: 7/7 CI workflows at `0466e7c4` | Development lab build/tests, not prod enrollment |
| [QA queue/restart PR #96](https://github.com/suhaylx/EDR/pull/96) | **PASS**: 4/4 CI at `ce261a4b` | Disposable PostgreSQL scan jobs, not SOC telemetry |
| [P0 claim/revocation PR #123](https://github.com/suhaylx/EDR/pull/123) | **PASS**: 9/9 CI at `9052875f` | Reviewable draft changes not integrated/approved |
| [API/ClamAV synthetic PR #132](https://github.com/suhaylx/EDR/pull/132) | **PASS**: 4/4 CI at `50ad5211` | In-process HTTP and synthetic socket fixtures |
| [DLL Event7/11 PR #134](https://github.com/suhaylx/EDR/pull/134) | **PASS**: 3/3 CI at `840f0682` | Synthetic events, not a real Windows collector |
| [Loopback guard PR #119](https://github.com/suhaylx/EDR/pull/119) | **PASS**: 3/3 CI at `ebdaccda` | Draft fix for lab bearer listener, unmerged |
| New SOC [#149](https://github.com/suhaylx/EDR/pull/149), [#150](https://github.com/suhaylx/EDR/pull/150), [#152](https://github.com/suhaylx/EDR/pull/152) | **CI FAIL / TESTS UNVERIFIED** | No runner execution steps observed; see [#153](https://github.com/suhaylx/EDR/issues/153) |
| [QA SOC SQL fix #161](https://github.com/suhaylx/EDR/pull/161) | **CI FAIL / TESTS UNVERIFIED** | [Starter run 44936038493](https://github.com/suhaylx/EDR/actions/runs/44936038493) and [PG run 44936038392](https://github.com/suhaylx/EDR/actions/runs/44936038392) report 0 steps |
| Sprint QA #144/#146/#147 and rotation #156 | **CI FAIL / TESTS UNVERIFIED** | Same Actions runner evidence gap [#148](https://github.com/suhaylx/EDR/issues/148) |

**Status semantics:** PASS means a named historical GitHub CI workflow completed successfully at the listed SHA. CI FAIL means GitHub reported workflow failure; when jobs have 0 executed steps this is **not** a proven failing test assertion. NOT RUN means no execution evidence. Planned features and draft PRs are never PASS automatically.

## Findings and release blockers (priority ordered)

| ID | Priority | Scope | Finding / acceptance decision | Evidence / owner |
| --- | --- | --- | --- | --- |
| QA-01 | P0 | CI | GitHub Actions runner assignment/step logging unavailable for newer PRs; cannot independently validate 0001–0012 migration chain, Go tests or Rust builds on latest backend head | [#153](https://github.com/suhaylx/EDR/issues/153), [#148](https://github.com/suhaylx/EDR/issues/148) — Agent 2 |
| QA-02 | P0 | Backend SOC | **Confirmed source defect:** endpoint inventory CTE projects anonymous COALESCE values but outer SQL refers to named columns; list/detail queries will not resolve. Existing Go test uses mocked DB rows and does not execute SQL | [#162](https://github.com/suhaylx/EDR/issues/162), proposed [#161](https://github.com/suhaylx/EDR/pull/161) — Agent 2, QA retest |
| QA-03 | P0 | Device auth | Lab `backend/cmd/server/main.go` starts an in-memory bearer-token HTTP API; dedicated `NewAgentMTLSServer` and registry are **components**, not a verified deployed Rust client enrollment and heartbeat integration | [#103](https://github.com/suhaylx/EDR/issues/103), [#119](https://github.com/suhaylx/EDR/pull/119) — Agents 1/2 |
| QA-04 | P0 | Data integrity | Durable PostgreSQL **scan-job** queue tested historically, but SOC events/offline endpoint spool, ACK idempotency and crash/reconnect are not established | [#104](https://github.com/suhaylx/EDR/issues/104) — Agent 2 |
| QA-05 | P0 | SOC operator auth | New operator mTLS, viewer/scanner roles, tenant inventory and analyst case APIs exist on draft #149–152; real PostgreSQL + TLS cross-tenant/role execution on final SHA **NOT RUN** | [#154](https://github.com/suhaylx/EDR/issues/154), [#155](https://github.com/suhaylx/EDR/issues/155) — Agents 1/2/3 |
| QA-06 | P0 | Authorization races | Scan claim/completion vs tenant/agent revocation regressions green only in draft #123; certificate rotation vs concurrent tenant disablement proposal #156 remains unexecuted and unreviewed | [#128](https://github.com/suhaylx/EDR/issues/128), [#157](https://github.com/suhaylx/EDR/issues/157) — Agents 1/2 |
| QA-07 | P0 | Release integrity | No independent InfoSec written approve on final integrated SHA, no signed installer/binary provenance, Windows/Linux production host signoff, audited rollback or deployment owner approval | [#43](https://github.com/suhaylx/EDR/issues/43), [#45](https://github.com/suhaylx/EDR/issues/45) — Agents 1/2/3 |
| QA-08 | P1 | Frontend/API contract | React frontend uses lab `/api/*` + in-memory shared token; new SOC operator routes use `/soc/v1/tenants/{tenant}/...`. No verified frontend connection to the operator API or approved browser session design | [#4](https://github.com/suhaylx/EDR/issues/4), [#135](https://github.com/suhaylx/EDR/issues/135) — Agents 2/5/1 |
| QA-09 | P1 | Accessibility | TS/Node tests and build green on older lab; actual browser keyboard focus, 200–400% zoom, screen reader, XSS text escaping and desktop UI/core process isolation **NOT RUN** | [#135](https://github.com/suhaylx/EDR/issues/135) — Agent 5, Agent 3 |
| QA-10 | P1 | AV | ClamAV INSTREAM clean-vs-ERROR and named EICAR signature simulations pass historically. Official clamd + signed DB, benign/EICAR-only host scan, timeouts and quick/full scheduling **NOT RUN** | [#17](https://github.com/suhaylx/EDR/issues/17) — Agents 1/2/3 |
| QA-11 | P1 | Telemetry | Synthetic Sysmon Event 7 ImageLoad vs Event 11 FileCreate and Linux procfs provenance tests exist; actual Event 1–29/255 availability, Event 7 noise loss, Linux collector continuity **NOT RUN** | [#105](https://github.com/suhaylx/EDR/issues/105), [#45](https://github.com/suhaylx/EDR/issues/45) |
| QA-12 | P1 | Update and tamper | Sysmon policy signature/rollback, worker crash isolation, resource exhaustion, maintenance permits, AD/LDAPS/GPO dry-run and tamper resistance remain unverified | [#105](https://github.com/suhaylx/EDR/issues/105), [#106](https://github.com/suhaylx/EDR/issues/106) — Agents 1/2/5 |

### P0 source finding detail: SOC endpoint inventory CTE

[Go source on new backend head](https://github.com/suhaylx/EDR/blob/a98adc46ff77474db78739f4e12b12a699a30702/backend/internal/edr/soc_endpoint_inventory.go): `endpointInventoryCTE` returns `COALESCE(h.agent_version,'')` without `AS agent_version`, likewise ClamAV/signature versions, `scan_ready` and `received_count`. `listEndpointsSQL` and `getEndpointSQL` then select the missing projected names. PostgreSQL resolves these anonymous expressions to function-derived column names, not those source field names. This is a **source-confirmed query defect**; failing live SQL output has not been observed because current CI does not start jobs.

Proposed [draft PR #161](https://github.com/suhaylx/EDR/pull/161) on top of #152 adds aliases and a new test which extracts the **actual Go SQL query text** and evaluates list, detail and summary against disposable PostgreSQL fixtures (two tenants, same agent ID). No production database was accessed. Require actual [postgres-migration-chain](https://github.com/suhaylx/EDR/actions/runs/44936038392) success before approving.

## Cross-team review requests already issued

| Owner | Required next artifact | Objective acceptance |
| --- | --- | --- |
| Agent 2 — Backend/deployment | Fix/verify #162/#161, restore #153 CI, run migration chain on final #152 head, implement production mTLS listener+Rust client and durable telemetry | Exact SHA logs: Go race/vet, PG 16 migrations and real SQL, strict TLS tenant/role negative cases, restart, rollback; no deployment by QA |
| Agent 5 — Frontend | Typed adapter for operator `/soc/v1` read/mutation contracts, read-only viewer state, original accessible desktop/SOC UI | Browser-backed Playwright keyboard/zoom/XSS/session-expiry tests with actual screenshots; local UI/core isolation verified on host |
| Agent 1 — InfoSec | Review #152 + #161, two principal-revocation race branches, CA segregation, actor/audit integrity, signed commands, Event7 semantics | **Written APPROVE or CHANGES REQUESTED** at exact SHA; distinguish DB trigger audit from cryptographically tamper-proof evidence |
| Agent 3 — QA | Retest real DB inventory, operator mTLS/role, PKI/replay, event durability, ClamAV/EICAR and Sysmon host matrix | PASS/FAIL/NOT RUN with reproducible commands, log timestamps and SHA; independent release recommendation |
| Agent 4 — PM | Reconcile stacked branches, prioritization, required reviews and deployment dependencies | One canonical integration SHA with all required checks; do not claim branch PR success as merged production release |

Review requests are documented in GitHub issues [#2](https://github.com/suhaylx/EDR/issues/2), [#4](https://github.com/suhaylx/EDR/issues/4), [#1](https://github.com/suhaylx/EDR/issues/1), [#154](https://github.com/suhaylx/EDR/issues/154) and [#155](https://github.com/suhaylx/EDR/issues/155). They are **handoffs, not proof that the other agents have completed them**.

## Next acceptance sequence and objective GO/NO-GO

1. **Restore actual GitHub Actions execution** (#153/#148); capture runner IDs and real logs. No green status inferred from old SHA.
2. **Verify and integrate P0 SOC SQL projection repair** (#162/#161). Execute actual PostgreSQL list, detail and summary, plus tenant isolation and migration 0001–0012.
3. **Backend + InfoSec:** validate operator/agent CA separation, SAN, EKU, fingerprint, revocation, browser/operator session, viewer/scanner write denials, audit permissions, cross-tenant and stale command/lease replay.
4. **Frontend:** browser keyboard-only, 200%/400% font scaling, XSS-like identifier escaping, error/crash isolation, endpoint drilldowns and viewer/scanner restriction without fake successful UI state.
5. **Owner-operated host lab (22 Nov):** collect sanitized Windows Server 2022 Sysmon Event 1 and actual Event 7 only if enabled, Linux procfs/heartbeat, benign and EICAR-only official ClamAV results, scan queue lease/completion and controlled reboot/restart evidence. No malware beyond EICAR, no pasted secrets.
6. **Independent release gate:** Agent 1 explicit security signoff, Agent 2 deploy/rollback readiness, Agent 3 exact-head automated+host evidence, Agent 4 PM reconciliation. No live deployment before all P0 are green.

**Final verdict:** **PRODUCTION NO-GO / lab development only.** Backend SOC source defect is proposed for correction but **not yet verified by executable CI**; accessibility/host/enterprise acceptance is **NOT RUN**. No test-level failure fabricated, no merges, real-host access or deployment performed.
