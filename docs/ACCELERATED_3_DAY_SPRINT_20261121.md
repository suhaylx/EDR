# TuranSec enterprise EDR — accelerated 3-day sprint execution

**Execution checkpoint:** 2026-11-21, Asia/Tashkent. **Original calendar target:** Day 1 — Nov 21, Day 2 — Nov 22, Day 3 — Nov 23. The user requested performing all possible sprint work **now**, on Nov 21. These are three *workstreams executed in one pass*, **not three elapsed calendar days**, and no real host testing is invented.

**Authoritative repository:** private [suhaylx/EDR](https://github.com/suhaylx/EDR). **Current code change:** dependent [draft PR #142](https://github.com/suhaylx/EDR/pull/142), latest commit `d2ed639e62dfd0d1a2bc268e9be045e86e5f255b`, based on enrolled-heartbeat [draft PR #136](https://github.com/suhaylx/EDR/pull/136). **Release NO-GO.** No automatic merge to main or production deployment.

## Day 1 workstream — security integration (code delivered, current CI BLOCKED)

**Objective:** close critical mTLS listener and client-supplied identity spoofing gaps on the *actual heartbeat/scan-result Backend stack*, not on a disconnected security branch.

**Changed sources:**
- `backend/internal/edr/agent_mtls_server.go`: numeric loopback-only host and valid 1–65535 port, nonempty client CA, complete server keypair, TLS 1.3 and required verified client certificates, no TLS session tickets.
- `backend/internal/edr/agent_http.go`: clone headers, strip untrusted `Authorization`, tenant/device/user and forwarded client certificate identity headers before calling authenticated downstream handlers. Principal remains certificate-derived context; header stripping is defense in depth, not authentication.
- `backend/internal/edr/agent_mtls_scan_listener_security_test.go`: positive local binds, negative external/DNS/wildcard/malformed, incomplete trust.
- `backend/internal/edr/agent_http_untrusted_headers_test.go`: malicious headers denied/removed on verified context, original request unchanged.
- `.github/workflows/p0-agent-mtls-scan-listener.yml`: Linux Go race tests and Windows Go tests/vet.

**Validation:** parent `#129` exact head `14551ba47963591f8d98ebcd75b1a638b5e29882` had [starter CI 44933029190](https://github.com/suhaylx/EDR/actions/runs/44933029190) and [dedicated security CI 44933029184](https://github.com/suhaylx/EDR/actions/runs/44933029184) **2/2 PASS**, incl. Linux race and Windows. **This does not validate PR #142.** Re-running CI on PR #142 initially failed without a runner or steps; see Day 3.

## Day 2 workstream — authenticated heartbeat integration (code/tests delivered; no live PostgreSQL host)

**Objective:** connect the new security controls to the latest agent heartbeat and durable scan-result API of PR #136, avoiding duplicated agent enrollments.

**Changed tests:** `backend/internal/edr/agent_heartbeat_real_mtls_test.go` uses an actual loopback TLS 1.3 handshake with a generated local CA/client certificate, isolated fake SQL driver, and `AgentHTTPGuard` + real `AgentScanQueueHandler`. It verifies:
1. Enrolled agent `tenantA/win01` receives 204 and its SQL heartbeat is scoped to verified certificate identity even when malicious tenant/device/cert/bearer headers are present.
2. Cross-tenant route receives 403 before any SQL heartbeat write.
3. Missing client certificate is denied in the TLS handshake.
4. Revocation of the enrolled client is denied on an otherwise previously accepted HTTPS connection and never reaches the database.

**Parent evidence:** PR #136 head `c6d516642b81eeaa5d8fbab0c0f95ebffb635652` had [9/9 associated CI workflows PASS](https://github.com/suhaylx/EDR/pull/136), including Rust, PostgreSQL enrollment/revocation/rotation/scan queue/migration tests. New test is only an in-process simulator for SQL/HTTP; **not a live PostgreSQL integration or endpoint installation**.

**Still missing:** reproducible `backend/cmd/agentserver/main.go` binary, trusted version-pinned PostgreSQL SQL driver+go.sum, operator-managed PKI and host service startup, continuous Rust agent scheduler, real ClamAV/Sysmon telemetry.

## Day 3 workstream — QA, release decision and blockers

| Gate | Expected independent proof | Observed at current checkpoint |
| --- | --- | --- |
| New PR #142 exact-head CI | Linux Go race and Windows Go test/vet, backend starter, PG heartbeat migrations and Rust; all exact SHA | **BLOCKED/FAIL**. Initial [starter 44933823000](https://github.com/suhaylx/EDR/actions/runs/44933823000) and [dedicated 44933823037](https://github.com/suhaylx/EDR/actions/runs/44933823037) failed within seconds with **no allocated runner, no job steps and unavailable logs**. Retry failed again. Latest head `d2ed639e62dfd0d1a2bc268e9be045e86e5f255b` runs [starter 44933982956](https://github.com/suhaylx/EDR/actions/runs/44933982956) and [dedicated 44933983003](https://github.com/suhaylx/EDR/actions/runs/44933983003) likewise failed with missing job steps/logs. Root cause NOT VERIFIED; don't call this a code failure or a pass without test logs. |
| mTLS listener trust and header isolation | Exact-head code test and line-level Agent 1 InfoSec approval | **CODE COMMITTED, CI BLOCKED, FORMAL REVIEW NOT VERIFIED** |
| Genuine Go/PostgreSQL agentserver | Verified driver checksums, TLS daemon starts/stops, cert trust, tenant isolation, revoked lease and persistent heartbeat | **NOT RUN / BLOCKED** by driver bootstrap and real lab access |
| Rust Windows/Linux core | Actual agent service/installer, certificate lifecycle, supervised ClamAV and Sysmon | **NOT RUN** on real hosts |
| EICAR-safe ClamAV | EICAR-only authorized isolated Windows/Ubuntu scan, proper MALICIOUS/CLEAN_BY_SIGNATURE/ERROR states | **NOT RUN** |
| Windows Sysmon source evidence | EID 1/7/11/29 true RecordID and loss/visibility, EID11 != EID7 execution | **NOT RUN** |
| Original accessible React SOC | Tenant-safe 401/403/503, real browser keyboard/ARIA/200% zoom and truthful UNKNOWN/unscanned | **NOT RUN** on real browser |
| Security, QA and deployment decision | Independent InfoSec + QA review, signed build, owner-approved canary and rollback | **NO-GO**, no approvals |
 
**CI diagnosis:** Both failed runs expose `runner_id=0`, empty `steps` and no `logs_url` for all jobs; the log download endpoint returned `BlobNotFound`. This is **consistent with an execution/runner provisioning problem**, but the root cause cannot be confirmed from available evidence. Do not mark tests PASS. Request GitHub Actions runner/service restoration, then exact-head rerun; if steps execute and fail, fix the actual test/compiler issue before review. Local code environment could not reach private GitHub (`github.com` DNS unavailable), so a full independent checked-out repository build was also NOT RUN.

## Owner assignments and next actions

| Owner | Deadline (Asia/Tashkent) | Concrete action and acceptance |
| --- | --- | --- |
| Agent 1 InfoSec, P0 | 2026-11-21 23:10 | Review PR #142 mTLS trust, header spoofing and cert revocation test; original EID7/EID11 rules with safe fixtures; exact findings + formal review |
| Agent 2 Backend/Deployment, P0 | 2026-11-21 23:20 | Approved `backend/cmd/agentserver/main.go` driver/Go module hashes, TLS 1.3 server + PostgreSQL; run Go race+vet and genuine SQL/agent heartbeat/scan tests |
| Agent 3 QA, P0 | 2026-11-21 23:30 | Restore exact-head GitHub runner evidence; QA for real TLS, tenant, revoked session, PostgreSQL claim races and 2-host EICAR/Sysmon; PASS/FAIL/NOT RUN per case |
| Agent 5 Frontend/UX, P1 | 2026-11-21 23:40 | Original SOC heartbeat and ClamAV truthfulness, device unknown/revoked/offline, 401/403/503 and keyboard/ARIA screenshots; backend API + QA review |
| Agent 4 PM, P0 | 2026-11-21 23:50 | Save/reconcile this 3-day report, issue work orders and source-specific evidence, release **NO-GO** until all blockers cleared |

**Manual test commands (run only on authorized disposable environment):**
```sh
cd backend
go test -race -count=1 ./...
go vet ./...
cd ../agent
cargo test --all-targets
cd ../frontend
npm test
npm run build
```

Use actual supported package scripts and approved PostgreSQL disposable migrations. Never put PKI secrets, live malware, or customer's endpoint data into PR comments. User-authorized feature-branch work through November 28 is not blanket merge/deploy approval.

**Day 1 status:** CODE EVIDENCED, new exact-head CI BLOCKED. **Day 2 status:** IN-PROCESS mTLS+SQL TEST COMMITTED, acceptance BLOCKED. **Day 3 status:** QA MATRIX RECORDED, RELEASE NO-GO. **Three calendar days have not elapsed.**
