# Agent 3 QA — 25 blocker-resolution milestones (21 November 2026)

**Repository:** private suhaylx/EDR. **Integration baseline:** draft PR #49 at `0466e7c47f098ffdb83f7818eb6571e0d941aebe`. **QA stacked PR:** #96. This document is a QA acceptance plan, not proof of implementation or deployment. Do not infer that a build green means a production security feature is present.

**Scope:** software, tests, CI and safe design until the owner runs isolated Windows Server 2022/Ubuntu endpoint tests on 22 November. Never run live malware; EICAR only. Never contact the public lab hosts or use credentials in chat. Agent 2 owns deployment. Agent 1 owns security signoff. Agent 5 owns UI implementation. QA owns objective evidence.

**Legend:** CI PASS prior PR96 SHA = confirmed earlier CI only; CI PENDING new SHA = new tests wired but not yet reported; CI UNIT ONLY = synthetic/unit evidence only; CI BUILD ONLY = compilation, not OS integration; CI STUB ONLY = simulated ClamAV, not official signatures; BLOCKED = missing required production integration; NOT RUN = no execution evidence; HOST NOT RUN = deferred to owner lab.

## 25 sequential checkpoints and solutions

| M01 | P0 | mTLS listener and enrollment | BLOCKED | Agent 2 + Agent 1 |

**M01 resolution:** Replace shared bearer endpoint channel with RequireAndVerifyClientCert, trusted CA pinning, fingerprint + SAN device mapping; reject no/malformed/unknown cert. **Gate:** Go httptest TLS: no cert/expired/unknown denied, valid mapped cert accepted; real host tomorrow.

| M02 | P0 | Tenant-bound API authorization | BLOCKED | Agent 2 |

**M02 resolution:** Derive tenant and device only from validated certificate; enforce tenant scope in every read/write/query, never client-supplied tenant. **Gate:** Same agent_id in two tenants cannot read/claim/write each other's records.

| M03 | P0 | Certificate rotation and revocation | PARTIAL | Agent 2 + Agent 1 |

**M03 resolution:** Transactionally revoke old fingerprint, register replacement, deny disabled tenant/revoked device at claim AND completion. **Gate:** Post-commit separate-connection denial for both success and error; rotation old-cert denied.

| M04 | P0 | Anti-replay signed commands | BLOCKED | Agent 2 + Agent 1 |

**M04 resolution:** Bind command signature to tenant, device, operation, nonce, sequence, issued_at, expiry and immutable policy hash; persist nonce consumption. **Gate:** Reused nonce, old sequence, expired command and wrong-device signature rejected after restart.

| M05 | P0 | API operator RBAC and audit | BLOCKED | Agent 2 |

**M05 resolution:** Separate operator and endpoint auth; authorize scan/policy/investigation by tenant and role; log denied mutations without secrets. **Gate:** 401 unauthenticated, 403 unauthorized, 404 tenant-hidden; denied action makes zero state change.

| M06 | P0 | Concurrent PostgreSQL lease claim | CI PASS prior PR96 SHA | Agent 3 |

**M06 resolution:** Two connections contend on one row using SKIP LOCKED; winner-only completion; disposable CI database. **Gate:** Two-session test; no double lease, loser token rejected; see PR #96 first green SQL run.

| M07 | P0 | Expired lease replay resistance | CI PENDING new SHA | Agent 3 |

**M07 resolution:** Commit lease A, expire, recover, claim B, reject A, accept B, reject duplicate. **Gate:** New scripts/test-scan-job-replay-exhaustion.sh via disposable Postgres CI.

| M08 | P0 | Retry exhaustion terminal state | CI PENDING new SHA | Agent 3 |

**M08 resolution:** Max attempts=1; expire and recover to failed, never requeue or claim again. **Gate:** New SQL regression checks failed state and null token.

| M09 | P0 | Database restart and queue recovery | NOT RUN | Agent 2 + Agent 3 |

**M09 resolution:** Use disposable DB restart with committed pending/leased rows; recover expired lease and verify monotonic attempts. **Gate:** CI service restart or container recreate with persisted volume; verify before/after SQL snapshots; host test tomorrow.

| M10 | P0 | Offline durable telemetry spool | BLOCKED | Agent 2 |

**M10 resolution:** Bounded encrypted-at-rest local WAL/spool, per-source sequence and server-side idempotency key; flush after reconnect. **Gate:** Kill agent/network, restart agent/server; prove no silent loss, bounded queue and dedup.

| M11 | P0 | Heartbeat truthfulness | CI UNIT ONLY | Agent 2 + Agent 3 |

**M11 resolution:** Use server-received timestamp, <=5min online, >5min offline, unknown future/missing, 2-day offline age. **Gate:** Go overview boundary tests and 401 endpoint; actual host heartbeat tomorrow.

| M12 | P0 | Provenance and event chronology | CI UNIT ONLY | Agent 1 + Agent 2 |

**M12 resolution:** Keep raw received_at vs reported time, source record ID, observed vs reported graph edges; dedup by scoped source key. **Gate:** Reject invented parent GUID and cross-device edges; cap depth/max_nodes and no causal infection claims.

| M13 | P0 | Unified signed agent installer/service | BLOCKED | Agent 2 |

**M13 resolution:** One Rust core service/identity/installer; separately supervise ClamAV/Sysmon; verify signature, least-privilege ACLs and rollback. **Gate:** Windows/Linux install, upgrade, uninstall, reboot, component failure tests; host tomorrow.

| M14 | P0 | Worker isolation and resource caps | BLOCKED | Agent 2 + Agent 1 |

**M14 resolution:** Separate bounded worker tasks/processes; queue backpressure, CPU/memory/file limits, timeouts and watchdogs. **Gate:** Inject worker panic/hang/oversized event; core heartbeat and other scans continue.

| M15 | P0 | Security release evidence | BLOCKED | Agent 1 + Agent 3 |

**M15 resolution:** Require independent InfoSec approval, QA exact-head CI, reproducible artifacts and rollback evidence. **Gate:** No production release on branch CI alone; Agent 2 only deploys after signed gate.

| M16 | P1 | ClamAV clean vs EICAR | HOST NOT RUN | Agent 1 + Agent 3 |

**M16 resolution:** Managed official clamd/signature DB, loopback-only INSTREAM; use benign and EICAR only. **Gate:** Benign clean_by_signature, EICAR malicious, signed DB/version evidence; no real malware.

| M17 | P1 | ClamAV failure truthfulness | CI STUB ONLY | Agent 3 |

**M17 resolution:** Timeout, stopped daemon, bad signature DB, oversize/archive limit and unsupported quick/full report error/unscanned. **Gate:** Rust socket simulation CI; actual daemon fault injection on host tomorrow.

| M18 | P1 | DLL Event 11 vs Event 7 | CI UNIT ONLY | Agent 1 + Agent 3 |

**M18 resolution:** Never call file create execution; correlate actual ImageLoad with ProcessCreate GUID, signer and path. **Gate:** Synthetic create-only negative; load positive; missing Event7 => unknown not executed.

| M19 | P1 | Sysmon Event 7 tuning | BLOCKED | Agent 1 + Agent 2 |

**M19 resolution:** Versioned targeted ImageLoad policy by paths/process/signer; sampling budget, allowlist and dropped-event counters. **Gate:** Noisy benign DLL workload under capped CPU/log volume; audit excluded coverage.

| M20 | P1 | Sysmon config isolation and rollback | BLOCKED | Agent 2 + Agent 3 |

**M20 resolution:** Validate signed policy, keep known-good, exclusive apply lock, canary, verify health/hash; rollback without core restart. **Gate:** Malformed XML, crash, concurrent update and failed rollback leave core/ClamAV alive.

| M21 | P1 | Windows/Linux telemetry parity honesty | CI BUILD ONLY | Agent 2 + Agent 3 |

**M21 resolution:** Windows Sysmon source Event 1-29/255, Linux procfs observations clearly distinct; capability matrix per OS. **Gate:** Rust cross-platform builds and contract tests; host Event1/procfs tomorrow.

| M22 | P1 | SOC desktop accessibility | CI UNIT ONLY | Agent 5 + Agent 3 |

**M22 resolution:** Semantic controls, visible focus, keyboard graph/drilldowns, Escape, 200% font, contrast, screen-reader labels. **Gate:** Playwright keyboard/a11y smoke and manual Windows desktop screen reader; manual NOT RUN.

| M23 | P1 | Local UI crash isolation | BLOCKED | Agent 5 + Agent 3 |

**M23 resolution:** Unprivileged local UI over authenticated IPC, never direct policy/service mutation; core remains running on UI crash. **Gate:** Kill/restart UI during scan and Sysmon update; heartbeat/scan unaffected.

| M24 | P1 | AD/LDAPS safe deployment plan | BLOCKED | Agent 2 + Agent 1 |

**M24 resolution:** Read-only LDAPS with verified CA/hostname, scoped OU dry-run, signed MSI/GPO approval and immutable target snapshot. **Gate:** Invalid cert/OU/ACL/tenant denied; dry-run cannot install; domain lab later.

| M25 | P1 | Tamper, audit and maintenance | BLOCKED | Agent 1 + Agent 3 |

**M25 resolution:** Append-only tenant-scoped audit, signed one-time maintenance permits, protected update/rollback, rate limits and secret redaction. **Gate:** Replay/expired permit denied, normal-user stop denied, audit immutable and resource stress bounded.

## Release gating and sequencing

1. **First resolve M01–M05** (device mTLS, tenant RBAC, command replay, revocation). Do not expose the shared development bearer API outside localhost/SSH tunnel. PostgreSQL registry alone is not a production identity boundary.
2. **Verify M06–M08 in CI on exact QA head**, then implement M09 restart persistence and M10 offline spool. Do not confuse separate SQL connections with a database restart.
3. **Prove M11–M15** for truthful telemetry, worker failure isolation and independent security approval before any customer data or rollout.
4. **M16–M25** require CI plus later OS/domain/browser-specific acceptance. EICAR only; no live malware in ordinary endpoint labs.

## Evidence references

- [PR #49 integrated lab candidate](https://github.com/suhaylx/EDR/pull/49) — 7 reported green workflows at `0466e7c4`; production mTLS and persistent SOC telemetry not established.
- [PR #96 QA lease concurrency and replay](https://github.com/suhaylx/EDR/pull/96) — exact new-head CI required before marking new replay/exhaustion tests PASS.
- [Issue #2 backend enrollment](https://github.com/suhaylx/EDR/issues/2), [Issue #3 QA](https://github.com/suhaylx/EDR/issues/3), [Issue #4 UX](https://github.com/suhaylx/EDR/issues/4), [Issue #17 ClamAV](https://github.com/suhaylx/EDR/issues/17).

**Production verdict: NO-GO.** Passing development CI authorizes only a controlled lab candidate for review, not enterprise/customer deployment.
