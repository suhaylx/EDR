# Agent 3 QA — 25 blocker-resolution milestones (21 November 2026)

**Repository:** private suhaylx/EDR. **Integration baseline:** draft PR #49 at `0466e7c47f098ffdb83f7818eb6571e0d941aebe`. **QA stacked PR:** #96. This document is a QA acceptance plan, not proof of implementation or deployment. Do not infer that a build green means a production security feature is present.

**Scope:** software, tests, CI and safe design until the owner runs isolated Windows Server 2022/Ubuntu endpoint tests on 22 November. Never run live malware; EICAR only. Never contact the public lab hosts or use credentials in chat. Agent 2 owns deployment. Agent 1 owns security signoff. Agent 5 owns UI implementation. QA owns objective evidence.

**Legend:** CI PASS @bd240 = verified at test-bearing SHA `bd240bd6ac6e0c3a9888b5ff2fd8489d6c582e8a` (subsequent documentation commits require separate exact-head CI); CI UNIT ONLY = synthetic/unit evidence only; CI BUILD ONLY = compilation, not OS integration; CI STUB ONLY = simulated ClamAV, not official signatures; BLOCKED = missing required production integration; NOT RUN = no execution evidence; HOST NOT RUN = deferred to owner lab.

## 25 sequential checkpoints and solutions

### M01 — mTLS listener and enrollment (P0)

**Owner:** Agent 2 + Agent 1. **Status:** PARTIAL — mTLS constructor and guard tests exist; production startup and Rust client are blocked.

**Resolution:** Wire existing `NewAgentMTLSServer` and `AgentHTTPGuard` into an operator-controlled dedicated agent service with trusted client CA, fingerprint + SAN registry binding and real Rust TLS client; keep bearer-only lab API on loopback.

**Acceptance:** Go httptest TLS: no cert/expired/unknown denied, valid mapped cert accepted; real host tomorrow.

### M02 — Tenant-bound API authorization (P0)

**Owner:** Agent 2. **Status:** PARTIAL — guarded PostgreSQL scan-queue route exists; the shared-token SOC API is not tenant-scoped.

**Resolution:** Derive tenant and device only from validated certificate; enforce tenant scope in every read/write/query, never client-supplied tenant.

**Acceptance:** Same agent_id in two tenants cannot read/claim/write each other's records.

### M03 — Certificate rotation and revocation (P0)

**Owner:** Agent 2 + Agent 1. **Status:** PARTIAL.

**Resolution:** Transactionally revoke old fingerprint, register replacement, deny disabled tenant/revoked device at claim AND completion.

**Acceptance:** Post-commit separate-connection denial for both success and error; rotation old-cert denied.

### M04 — Anti-replay signed commands (P0)

**Owner:** Agent 2 + Agent 1. **Status:** BLOCKED.

**Resolution:** Bind command signature to tenant, device, operation, nonce, sequence, issued_at, expiry and immutable policy hash; persist nonce consumption.

**Acceptance:** Reused nonce, old sequence, expired command and wrong-device signature rejected after restart.

### M05 — API operator RBAC and audit (P0)

**Owner:** Agent 2. **Status:** BLOCKED.

**Resolution:** Separate operator and endpoint auth; authorize scan/policy/investigation by tenant and role; log denied mutations without secrets.

**Acceptance:** 401 unauthenticated, 403 unauthorized, 404 tenant-hidden; denied action makes zero state change.

### M06 — Concurrent PostgreSQL lease claim (P0)

**Owner:** Agent 3. **Status:** CI PASS @bd240.

**Resolution:** Two connections contend on one row using SKIP LOCKED; winner-only completion; disposable CI database.

**Acceptance:** Two-session test; no double lease, loser token rejected; see PR #96 first green SQL run.

### M07 — Expired lease replay resistance (P0)

**Owner:** Agent 3. **Status:** CI PASS @bd240.

**Resolution:** Commit lease A, expire, recover, claim B, reject A, accept B, reject duplicate.

**Acceptance:** New scripts/test-scan-job-replay-exhaustion.sh via disposable Postgres CI.

### M08 — Retry exhaustion terminal state (P0)

**Owner:** Agent 3. **Status:** CI PASS @bd240.

**Resolution:** Max attempts=1; expire and recover to failed, never requeue or claim again.

**Acceptance:** New SQL regression checks failed state and null token.

### M09 — Database restart and queue recovery (P0)

**Owner:** Agent 2 + Agent 3. **Status:** CI PASS @bd240 — actual disposable PostgreSQL service restart; application/endpoint restart NOT RUN.

**Resolution:** Maintain the disposable CI PostgreSQL container restart regression and separately add Go service/Rust endpoint restart and offline spool tests.

**Acceptance:** [GitHub Actions 44931373801](https://github.com/suhaylx/EDR/actions/runs/44931373801) verifies committed pending/leased/expired rows, post-restart claim, recovery, stale token denial and valid completion. This does not prove SOC event persistence or endpoint recovery.

### M10 — Offline durable telemetry spool (P0)

**Owner:** Agent 2. **Status:** BLOCKED.

**Resolution:** Bounded encrypted-at-rest local WAL/spool, per-source sequence and server-side idempotency key; flush after reconnect.

**Acceptance:** Kill agent/network, restart agent/server; prove no silent loss, bounded queue and dedup.

### M11 — Heartbeat truthfulness (P0)

**Owner:** Agent 2 + Agent 3. **Status:** CI UNIT ONLY.

**Resolution:** Use server-received timestamp, <=5min online, >5min offline, unknown future/missing, 2-day offline age.

**Acceptance:** Go overview boundary tests and 401 endpoint; actual host heartbeat tomorrow.

### M12 — Provenance and event chronology (P0)

**Owner:** Agent 1 + Agent 2. **Status:** CI UNIT ONLY.

**Resolution:** Keep raw received_at vs reported time, source record ID, observed vs reported graph edges; dedup by scoped source key.

**Acceptance:** Reject invented parent GUID and cross-device edges; cap depth/max_nodes and no causal infection claims.

### M13 — Unified signed agent installer/service (P0)

**Owner:** Agent 2. **Status:** BLOCKED.

**Resolution:** One Rust core service/identity/installer; separately supervise ClamAV/Sysmon; verify signature, least-privilege ACLs and rollback.

**Acceptance:** Windows/Linux install, upgrade, uninstall, reboot, component failure tests; host tomorrow.

### M14 — Worker isolation and resource caps (P0)

**Owner:** Agent 2 + Agent 1. **Status:** BLOCKED.

**Resolution:** Separate bounded worker tasks/processes; queue backpressure, CPU/memory/file limits, timeouts and watchdogs.

**Acceptance:** Inject worker panic/hang/oversized event; core heartbeat and other scans continue.

### M15 — Security release evidence (P0)

**Owner:** Agent 1 + Agent 3. **Status:** BLOCKED.

**Resolution:** Require independent InfoSec approval, QA exact-head CI, reproducible artifacts and rollback evidence.

**Acceptance:** No production release on branch CI alone; Agent 2 only deploys after signed gate.

### M16 — ClamAV clean vs EICAR (P1)

**Owner:** Agent 1 + Agent 3. **Status:** HOST NOT RUN.

**Resolution:** Managed official clamd/signature DB, loopback-only INSTREAM; use benign and EICAR only.

**Acceptance:** Benign clean_by_signature, EICAR malicious, signed DB/version evidence; no real malware.

### M17 — ClamAV failure truthfulness (P1)

**Owner:** Agent 3. **Status:** CI STUB ONLY.

**Resolution:** Timeout, stopped daemon, bad signature DB, oversize/archive limit and unsupported quick/full report error/unscanned.

**Acceptance:** Rust socket simulation CI; actual daemon fault injection on host tomorrow.

### M18 — DLL Event 11 vs Event 7 (P1)

**Owner:** Agent 1 + Agent 3. **Status:** CI UNIT ONLY.

**Resolution:** Never call file create execution; correlate actual ImageLoad with ProcessCreate GUID, signer and path.

**Acceptance:** Synthetic create-only negative; load positive; missing Event7 => unknown not executed.

### M19 — Sysmon Event 7 tuning (P1)

**Owner:** Agent 1 + Agent 2. **Status:** BLOCKED.

**Resolution:** Versioned targeted ImageLoad policy by paths/process/signer; sampling budget, allowlist and dropped-event counters.

**Acceptance:** Noisy benign DLL workload under capped CPU/log volume; audit excluded coverage.

### M20 — Sysmon config isolation and rollback (P1)

**Owner:** Agent 2 + Agent 3. **Status:** BLOCKED.

**Resolution:** Validate signed policy, keep known-good, exclusive apply lock, canary, verify health/hash; rollback without core restart.

**Acceptance:** Malformed XML, crash, concurrent update and failed rollback leave core/ClamAV alive.

### M21 — Windows/Linux telemetry parity honesty (P1)

**Owner:** Agent 2 + Agent 3. **Status:** CI BUILD ONLY.

**Resolution:** Windows Sysmon source Event 1-29/255, Linux procfs observations clearly distinct; capability matrix per OS.

**Acceptance:** Rust cross-platform builds and contract tests; host Event1/procfs tomorrow.

### M22 — SOC desktop accessibility (P1)

**Owner:** Agent 5 + Agent 3. **Status:** CI UNIT ONLY.

**Resolution:** Semantic controls, visible focus, keyboard graph/drilldowns, Escape, 200% font, contrast, screen-reader labels.

**Acceptance:** Playwright keyboard/a11y smoke and manual Windows desktop screen reader; manual NOT RUN.

### M23 — Local UI crash isolation (P1)

**Owner:** Agent 5 + Agent 3. **Status:** BLOCKED.

**Resolution:** Unprivileged local UI over authenticated IPC, never direct policy/service mutation; core remains running on UI crash.

**Acceptance:** Kill/restart UI during scan and Sysmon update; heartbeat/scan unaffected.

### M24 — AD/LDAPS safe deployment plan (P1)

**Owner:** Agent 2 + Agent 1. **Status:** BLOCKED.

**Resolution:** Read-only LDAPS with verified CA/hostname, scoped OU dry-run, signed MSI/GPO approval and immutable target snapshot.

**Acceptance:** Invalid cert/OU/ACL/tenant denied; dry-run cannot install; domain lab later.

### M25 — Tamper, audit and maintenance (P1)

**Owner:** Agent 1 + Agent 3. **Status:** BLOCKED.

**Resolution:** Append-only tenant-scoped audit, signed one-time maintenance permits, protected update/rollback, rate limits and secret redaction.

**Acceptance:** Replay/expired permit denied, normal-user stop denied, audit immutable and resource stress bounded.

## Release gating and sequencing

1. **First resolve M01–M05** (device mTLS, tenant RBAC, command replay, revocation). Do not expose the shared development bearer API outside localhost/SSH tunnel. PostgreSQL registry alone is not a production identity boundary.
2. **M06–M09 passed in disposable PostgreSQL CI at `bd240`**, including an actual CI container restart. Next implement M10 offline telemetry spool and Go/agent restart tests. Do not confuse PostgreSQL scan-job persistence with durable SOC events.
3. **Prove M11–M15** for truthful telemetry, worker failure isolation and independent security approval before any customer data or rollout.
4. **M16–M25** require CI plus later OS/domain/browser-specific acceptance. EICAR only; no live malware in ordinary endpoint labs.

## Evidence references

- [PR #49 integrated lab candidate](https://github.com/suhaylx/EDR/pull/49) — 7 reported green workflows at `0466e7c4`; production mTLS and persistent SOC telemetry not established.
- [PR #96 QA concurrency, replay, DB restart and mTLS constructor tests](https://github.com/suhaylx/EDR/pull/96) — [PostgreSQL CI PASS](https://github.com/suhaylx/EDR/actions/runs/44931373801) and [Go race/starter CI PASS](https://github.com/suhaylx/EDR/actions/runs/44931373689) at `bd240`; verify any newer exact head before release.
- [Issue #2 backend enrollment](https://github.com/suhaylx/EDR/issues/2), [Issue #3 QA](https://github.com/suhaylx/EDR/issues/3), [Issue #4 UX](https://github.com/suhaylx/EDR/issues/4), [Issue #17 ClamAV](https://github.com/suhaylx/EDR/issues/17).
- Implementation blockers: [#103 mTLS startup/client](https://github.com/suhaylx/EDR/issues/103), [#104 durable telemetry](https://github.com/suhaylx/EDR/issues/104), [#105 Sysmon policy isolation](https://github.com/suhaylx/EDR/issues/105), [#106 AD/LDAPS dry-run](https://github.com/suhaylx/EDR/issues/106).

**Production verdict: NO-GO.** Passing development CI authorizes only a controlled lab candidate for review, not enterprise/customer deployment.


---

# Next 25 QA milestones — M26–M50

**Evidence snapshot, 21 November 2026.** Passing branch CI proves only the exercised test boundary. New PRs are draft and may not be merged; any unverified CI is explicitly marked pending. Actual endpoint/AD/ClamAV host tests remain scheduled for the owner on 22 November.

### M26 — PR96 exact-head baseline

**Owner:** Agent 3. **Evidence status:** VERIFIED PASS.

**Proposed implementation / resolution:** Record all 4 GitHub workflow conclusions at `807e329e`, keep branch draft and no deploy.

**Objective QA gate:** All Go race, Postgres restart, Ubuntu/Windows CI success; no host claims.

### M27 — Development API loopback guard

**Owner:** Agent 3 proposes; Agent 2 reviews. **Evidence status:** CODE + CI PASS (draft PR119).

**Proposed implementation / resolution:** Refuse public, wildcard and LAN EDR_ADDR for bearer-only Go lab server; use SSH loopback tunnel.

**Objective QA gate:** No unencrypted bearer HTTP on routable interfaces; Agent2 approval before merge.

### M28 — Bind-target negative input matrix

**Owner:** Agent 3. **Evidence status:** 25 TEST CASES CI PASS (draft PR119).

**Proposed implementation / resolution:** Table-driven Go test with numeric IPv4/IPv6 loopback and 19 bad DNS/IP/port inputs.

**Objective QA gate:** 25 named subtests pass in PR119 starter CI.

### M29 — Claim vs agent revocation race

**Owner:** Agent 3 QA; Agent 2 fixes SQL. **Evidence status:** CI PASS at PR123 commit `912cfa0959b5ca7e366ed2ad6f5f823f38392cdc`, unmerged.

**Proposed implementation / resolution:** Share-lock principal rows during scan claim; leave SKIP LOCKED on job row.

**Objective QA gate:** Separate sessions: deny post-commit revoked agent; observe lock wait before release.

### M30 — Claim vs tenant disable race

**Owner:** Agent 3 QA; Agent 2 fixes SQL. **Evidence status:** CI PASS at PR123 commit `912cfa0959b5ca7e366ed2ad6f5f823f38392cdc`, unmerged.

**Proposed implementation / resolution:** Serialize tenant disabled_at update and scan claim in disposable DB.

**Objective QA gate:** Two concurrent sessions: disabled tenant never receives lease after admin commit.

### M31 — Completion vs revoked agent race

**Owner:** Agent 3. **Evidence status:** PostgreSQL CI PASS at PR123 head `9052875fea7c2ebd63acbcebbb4178b25c392967`; draft/unmerged.

**Proposed implementation / resolution:** Build transaction-level test with admin update in-flight and completion waiting on FOR SHARE.

**Objective QA gate:** Record lock wait and denied completion after admin commit; unchanged lease.

### M32 — Completion vs disabled tenant race

**Owner:** Agent 3. **Evidence status:** PostgreSQL CI PASS at PR123 head `9052875fea7c2ebd63acbcebbb4178b25c392967`; draft/unmerged.

**Proposed implementation / resolution:** Build parallel disable vs completion regression on separate-session PostgreSQL transactions.

**Objective QA gate:** Denied completion after committed tenant disable; no success/failure mutation.

### M33 — TLS cert identity and strict SAN

**Owner:** Agent 2 + Agent 3. **Evidence status:** UNIT CI ONLY.

**Proposed implementation / resolution:** Keep VerifyAgentCertificate peer/chain/fingerprint checks; add TLS valid/expired/rotated/SAN pinning cases.

**Objective QA gate:** Strong TLS 1.3 mTLS end-to-end with real PostgreSQL registry, not only mocked records.

### M34 — Enrollment challenge and rotation restart

**Owner:** Agent 2 + Agent 3. **Evidence status:** PARTIAL, DATABASE CI ONLY.

**Proposed implementation / resolution:** Persist single-use challenge digest, certificate revocation and issuance audit transactionally.

**Objective QA gate:** Consumed challenge and old cert stay rejected after real disposable PostgreSQL restart.

### M35 — Dedicated production mTLS listener startup

**Owner:** Agent 2. **Evidence status:** BLOCKED #103.

**Proposed implementation / resolution:** Wire existing NewAgentMTLSServer on a dedicated port with injected CA/server key/db; separate operator vs endpoint API.

**Objective QA gate:** Real Rust client without bearer, tenant-bound endpoint route; no insecure fallback.

### M36 — Rust mTLS key custody/rotation

**Owner:** Agent 2 + Agent 1. **Evidence status:** BLOCKED #103.

**Proposed implementation / resolution:** OS keystore-backed key, CSR proof, pinned trust and expiry rotation without exposing secrets.

**Objective QA gate:** Windows/Linux build and negative cert rotation/expired/missing-key tests; host tomorrow.

### M37 — Tenant-scoped heartbeat endpoint

**Owner:** Agent 2. **Evidence status:** BLOCKED #103.

**Proposed implementation / resolution:** Persist server-received heartbeats with cert principal and dedup; reject headers pretending another agent.

**Objective QA gate:** Wrong-tenant/wrong-device heartbeat cannot update presence; offline >5min truthful.

### M38 — Tenant-safe raw event ingestion

**Owner:** Agent 2. **Evidence status:** BLOCKED #104.

**Proposed implementation / resolution:** Authorize every event via cert identity, keep source ID/received_at; reject cross-device attribution.

**Objective QA gate:** Attacker-controlled device_id not trusted, server ACK after committed event, no cross-tenant query.

### M39 — Operator RBAC on SOC queries

**Owner:** Agent 2 + Agent 5. **Evidence status:** BLOCKED #103.

**Proposed implementation / resolution:** Role/tenant filter on overview, investigation, telemetry, rules and incident graph.

**Objective QA gate:** Two-tenant fixture yields 403/404 for unauthorized paths, zero evidence leakage.

### M40 — Expiry/nonce and signed response commands

**Owner:** Agent 1 + Agent 2. **Evidence status:** BLOCKED.

**Proposed implementation / resolution:** Sign tenant+agent+op+seq+nonce+TTL+policy hash and persist replay watermark.

**Objective QA gate:** Wrong-device, duplicate, expired and rollback commands fail closed across restart.

### M41 — Offline Rust spool with bounded resources

**Owner:** Agent 2. **Evidence status:** BLOCKED #104.

**Proposed implementation / resolution:** On-disk append/ACK journal with cap, encryption, quotas, backpressure and gap counters.

**Objective QA gate:** Crash/reboot/offline reconnect replays once without unbounded RAM or forged event counts.

### M42 — Durable SOC events through DB restart

**Owner:** Agent 2 + Agent 3. **Evidence status:** BLOCKED #104.

**Proposed implementation / resolution:** Store raw events and tenant scopes durably, distinct from already-tested scan-job queue.

**Objective QA gate:** Kill/restart disposable ingest DB, assert chronological history/replay provenance retained.

### M43 — Event ingest idempotency/crash before ACK

**Owner:** Agent 2 + Agent 3. **Evidence status:** BLOCKED #104.

**Proposed implementation / resolution:** Use `(tenant,agent,source_id,record_id)` dedup key, committed ACK, cursor persistence.

**Objective QA gate:** Duplicate event/report and process restart yield one retained event and explicit loss accounting.

### M44 — ClamAV benign/EICAR signature attestation

**Owner:** Agent 1 + Agent 3. **Evidence status:** STUB CI ONLY; HOST NOT RUN.

**Proposed implementation / resolution:** Use official signed ClamAV DB with EICAR-only, benign, stopped daemon, scanner ERROR semantics.

**Objective QA gate:** No malicious live sample; clean_by_signature != safe; host run tomorrow.

### M45 — DLL Event 11 vs Event 7, noise budget

**Owner:** Agent 1 + Agent 3. **Evidence status:** UNIT CI ONLY; HOST NOT RUN.

**Proposed implementation / resolution:** Correlate ImageLoad actual Event7 with Event1 host, treat Event11 as creation only; targeted noise thresholds.

**Objective QA gate:** Synthetic negative/positive fixtures and server workload Event7 sampling; no false causal claim.

### M46 — Sysmon policy update isolation/rollback

**Owner:** Agent 2 + Agent 3. **Evidence status:** BLOCKED #105.

**Proposed implementation / resolution:** Signed per-OS config, exclusive apply lock, separate worker, known-good revision+hash and auto rollback.

**Objective QA gate:** Malformed XML, timeout, failed rollback, concurrent updates preserve core PID/heartbeat/ClamAV.

### M47 — Windows/Linux unified Rust agent parity

**Owner:** Agent 2 + Agent 3. **Evidence status:** BUILD CI ONLY; HOST NOT RUN.

**Proposed implementation / resolution:** One agent identity/install, report capability gaps, preserve original source fidelity.

**Objective QA gate:** Cross-OS compile/contract checks; actual Sysmon and Linux /proc host evidence tomorrow.

### M48 — SOC and local UI accessible/non-disruptive

**Owner:** Agent 5 + Agent 3. **Evidence status:** NODE UNIT ONLY; BROWSER NOT RUN.

**Proposed implementation / resolution:** Keyboard tab order, Enter/Space graph, focus restoration, 200% zoom, error boundary, unprivileged local IPC.

**Objective QA gate:** No UI crash changes core scan/heartbeat; screen-reader and actual desktop test pending.

### M49 — AD/LDAPS dry-run and tamper audit

**Owner:** Agent 2 + Agent 1 + Agent 3. **Evidence status:** BLOCKED #106.

**Proposed implementation / resolution:** Read-only pinned LDAPS OU targeting and plan-only GPO; one-time signed maintenance and insert-only audit.

**Objective QA gate:** Untrusted DC/replay/OU scope denied, no unauthorized deployment or silent disable.

### M50 — Final security/QA release decision

**Owner:** Agent 1 + Agent 3 + PM. **Evidence status:** PRODUCTION NO-GO.

**Proposed implementation / resolution:** Gate InfoSec review, exact SHA reproducibility, signed installers, host evidence, rollout/rollback and all P0 race checks.

**Objective QA gate:** NO-GO until all P0 satisfied; Agent2 alone handles any approved deployment.

## Review and evidence links for M26–M50

- [PR #96 — scan lease concurrency, replay, restart, Go race](https://github.com/suhaylx/EDR/pull/96): exact head `807e329e98417180716a688bd0b3412b3955c268`, all 4 CI workflows reported PASS before this documentation update.
- [PR #119 — loopback-only shared-token lab listener, 25 named Go test cases](https://github.com/suhaylx/EDR/pull/119): all 3 reported CI workflows PASS at `f0d453100126dffb8afe00d2d0f252e9805deafa`, draft.
- [PR #123 — claim and completion vs revocation race](https://github.com/suhaylx/EDR/pull/123): [PostgreSQL queue CI PASS](https://github.com/suhaylx/EDR/actions/runs/44932462150) at `9052875fea7c2ebd63acbcebbb4178b25c392967`, including all four lock-wait cases; other workflows verified separately. Draft, Agent 2/InfoSec review required.
- [Issue #103 mTLS startup](https://github.com/suhaylx/EDR/issues/103), [#104 durable telemetry](https://github.com/suhaylx/EDR/issues/104), [#105 Sysmon isolation](https://github.com/suhaylx/EDR/issues/105), [#106 AD/LDAPS](https://github.com/suhaylx/EDR/issues/106).

**Release:** NO-GO for any customer/production use. No live endpoint or domain controller contacted by QA.


---

# M51–M75: Agent API negative-security acceptance milestones

**Status:** 25 named, executable in-process Go table-driven subtests committed as a single QA-only file in [draft PR #132](https://github.com/suhaylx/EDR/pull/132), test-bearing SHA `50ad5211fc03e7cdbc548243acdc91f16e28d33f`. [Starter CI](https://github.com/suhaylx/EDR/actions/runs/44932955330) completed successfully, exercising the Go and Rust tests. The lab handler receives an injected test principal; this is **not** evidence that real mTLS endpoint enrollment or multi-tenant deployment works. These are independent negative-response contracts within one test suite, **not 25 completed enterprise product features**.

**Each gate additionally requires:** `Cache-Control: no-store`, no serialized lease token or scan root on denied requests, and `Allow: POST` for incorrect HTTP methods. All tests use a deliberately unconnected storage adapter, preventing external DB mutation.

| Gate | Test requirement | Expected HTTP status |
|---|---|---|
| M51 | Missing identity cannot claim | 401 |
| M52 | Missing identity cannot complete | 401 |
| M53 | Wrong-tenant claim denied | 403 |
| M54 | Wrong-device claim denied | 403 |
| M55 | Wrong-tenant completion denied | 403 |
| M56 | Wrong-device completion denied | 403 |
| M57 | GET cannot claim | 405 |
| M58 | PUT cannot claim | 405 |
| M59 | DELETE cannot claim | 405 |
| M60 | GET cannot complete | 405 |
| M61 | PATCH cannot complete | 405 |
| M62 | Unknown high-risk command never exposed | 404 |
| M63 | Claim query override rejected | 400 |
| M64 | Completion query override rejected | 400 |
| M65 | Empty completion body rejected | 400 |
| M66 | Malformed JSON rejected | 400 |
| M67 | JSON array in place of object rejected | 400 |
| M68 | Null completion object rejected | 400 |
| M69 | Missing success flag rejected | 400 |
| M70 | Null success flag rejected | 400 |
| M71 | String masquerading as boolean rejected | 400 |
| M72 | Malformed job UUID rejected | 400 |
| M73 | Malformed lease token rejected | 400 |
| M74 | Unexpected tenant field rejected | 400 |
| M75 | Trailing JSON object rejected | 400 |

## Additional P1 evidence from this checkpoint

- [Draft PR #132](https://github.com/suhaylx/EDR/pull/132) also includes Rust **synthetic** ClamAV parsing regressions: malformed/invalid bytes, scanner ERROR not CLEAN, named EICAR signature reply, cap/truncation and oversized-response denial. These tests do **not** run an official ClamAV daemon or signature database.
- [Draft PR #134](https://github.com/suhaylx/EDR/pull/134) adds Event 7 / Event 11 pure Go evidence tests: no FileCreate-as-execution, source identity, hash/boot/process/time scope, duplicate suppression and no confirmed infection claims. **Real Windows collection and Event 7 noise measurements NOT RUN**.
- The previous P0 tenant/agent claim and completion revocation race is addressed for review in [draft PR #123](https://github.com/suhaylx/EDR/pull/123) with [disposable PostgreSQL CI PASS](https://github.com/suhaylx/EDR/actions/runs/44932462150).

## Outstanding gates after M75

- [#103](https://github.com/suhaylx/EDR/issues/103): production device mTLS startup/client, tenant-bound auth and replay on real endpoints.
- [#104](https://github.com/suhaylx/EDR/issues/104): durable event/spool, acknowledgement/dedup and restart recovery (database *scan jobs* are already separately tested).
- [#105](https://github.com/suhaylx/EDR/issues/105): Sysmon config update rollback, worker isolation/resource limits, Event 7 tuning on Windows.
- [#106](https://github.com/suhaylx/EDR/issues/106): AD/LDAPS read-only discovery and GPO dry-run, pending domain lab.
- [#4](https://github.com/suhaylx/EDR/issues/4): Agent 5 browser keyboard/screen-reader/font-scaling, desktop local UI crash-isolation acceptance; no real browser execution claimed.

**QA decision: PRODUCTION NO-GO.** Deployment belongs to Agent 2; real Windows/Linux, official EICAR-only ClamAV and AD host tests remain with the owner tomorrow. All code/CI review must be pinned to exact SHA; do not infer PASS for newly edited heads.
