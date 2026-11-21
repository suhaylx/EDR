# P0 Lab Acceptance Matrix — 2026-11-21

**Scope:** Local development Go API, not production EDR or endpoint telemetry.

| Test | Evidence / command | Actual result | Release gate |
| --- | --- | --- | --- |
| Go API unit tests, scan idempotency, expiry and wrong-agent rejection | `cd backend && go test -count=1 ./...` | PASS (local) | Development |
| Concurrent scan leasing and race detector | `cd backend && go test -race -count=1 ./...` | PASS (local) | Development |
| Go static analysis | `cd backend && go vet ./...` | PASS (local) | Development |
| Frontend syntax | `node --check backend/web/app.js` | PASS (local) | Development |
| API unauthorized scan listing | HTTP GET `/api/scan-jobs` without token | HTTP 401 (local smoke) | Development |
| API request queued, not executed | `scripts/demo-scan-workflow.sh` with localhost only | Queued command shown (local smoke) | Development |
| Production per-device mTLS and cross-tenant isolation | Windows/Linux lab not provisioned | NOT RUN | BLOCKER |
| Rust clamd INSTREAM module compiled and verified | Rust compiler unavailable in local execution environment | NOT RUN | BLOCKER |
| Live ClamAV 1.5.5 EICAR signature scan | ClamAV binary/signature database unavailable | NOT RUN | BLOCKER |
| Windows Sysmon Events 1, 7, 11 and rollback | Windows VM not connected | NOT RUN | BLOCKER |
| Windows/Linux agent install and tamper prevention | Not implemented | NOT RUN | BLOCKER |
| Performance, false positives, offline queue, durable persistence | Not implemented | NOT RUN | BLOCKER |

Agent 3 requires repeatable positive and negative evidence before any production approval. A synthetic result does not prove a real ClamAV scan occurred.
