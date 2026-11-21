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
