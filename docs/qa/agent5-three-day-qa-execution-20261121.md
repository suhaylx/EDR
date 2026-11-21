# TuranSec EDR — Agent 5 three-day QA execution report

**Execution date:** 2026-11-21 Asia/Tashkent (three consecutive sprint
acceptance phases executed in one session, not 72 elapsed hours).

**Private repository:** `suhaylx/EDR`. Feature branch:
`qa/agent5-three-day-security-acceptance-20261121`,
stacked on draft PR #166 → #158 → #151 and related frontend/backend
branches. The branch is **draft, unmerged and undeployed**.

## Actual executed QA evidence — focused isolated suites

The GitHub connector exposed the **exact source and test file bytes**;
the current work container cannot clone the private GitHub repository
(DNS resolution for github.com unavailable), and GitHub Actions jobs
are failing before runner allocation. For an honest executable subset,
the following source/test files were copied into a disposable local
workspace. We verified each copied file with `git hash-object` against
the **Git blob SHA** of that same file in the private branch.
Compilation and tests then ran against those verified bytes. Minimal
TypeScript `.d.ts` stubs in the isolated workspace supply only type
declarations for other lab modules; they do not simulate the full app.
No code changes were inferred from test output.

| Day | Verified files (Git blob SHA) | Local execution | Outcome |
|---|---|---|---|
| **1 — Frontend refresh/QA** | `frontend/src/lab-refresh.ts` `0a52b43c99657122c1f021ff2e5525d628e292f8`; `frontend/tests/qa-three-day-atomic-refresh.test.mjs` `30e75a21b80e76e9f748d69eb3b0771d7270b226` | Global TypeScript `tsc --strict` on actual helper; `node --test` | **7/7 passed** |
| **2 — Backend auth/QA** | `backend/internal/edr/lab_auth.go` `f5e6068723024f0f8a5661ce5aa8f00540b41bee`; `backend/internal/edr/lab_auth_test.go` `61c0d49bfea8c2150f8c039b3b089e8c32eabfcb` | Local isolated Go package `go test -count=1 -v ./...` and `go vet ./...` | **13/13 subtests passed; vet passed** |
| **3 — Backend-aligned frontend regressions** | `backend-utc-window.ts` `975e275287ca1311bfaa36e7e98a062bb716fc7b`; `policy-readonly.ts` `7f05f319e3d7280aa30142af406a76e42fc29e0f`; `scan-lifecycle.ts` `3a358fa38eee4411a637e406c0529d3cf48c3e4a`; `qa-three-day-cross-contract.test.mjs` `ec9a8c7afcb7c543285cc31656d99e21dd37849e` | Global TypeScript `tsc --strict` on exact pure models with local declaration stubs; `node --test` | **11/11 passed** |

**Focused results: 31/31 executed checks passed; 0 failed.**
This is genuine **isolated-source** verification, **not a whole-repository
frontend/backend/Windows test pass**. The exact branch commit must be
checked again after further changes.

## Detailed acceptance

**Day 1: React six-source consistency**

- A successful refresh yields exactly six values in source order.
- A failed scan request or policy metadata source rejects the **entire**
  result, never publishes a partial overview.
- All six independent sources launch; a prior abort launches none.
- A late response from a fetch adapter that ignores cancellation
  cannot commit after the supplied signal is aborted.
- Fresh reload succeeds after a previous aborted refresh.
- `frontend/src/main.tsx` now uses the helper; prior data clearing,
  abort-on-token/disconnect/UTC-window-change and no-store auth remain.

**Day 2: Go authentication**

- Confirmed code defect: Go `strings.TrimPrefix(Authorization,"Bearer ")`
  would accept a bare header equal to the secret.
- `backend/internal/edr/lab_auth.go` now requires the exact
  `Bearer ` prefix and constant-time comparison, and `http.go`
  calls the helper on all development `/api/` routes.
- Thirteen direct Go cases passed: correct token, no header, bare
  token, Basic, lower-case scheme, unknown scheme, no separator,
  double separator, wrong token, appended suffix, trailing space,
  empty configured secret, non-empty header with empty configured
  secret.
- Added **full-handler** Go regression file
  `qa_three_day_bearer_test.go`: deny matrix across nine read APIs,
  unauthorized policy POST, `Cache-Control: no-store`, and protection
  of the two metadata routes. **These full-handler tests are committed
  but not executed locally**, since the complete private Go package
  cannot be checked out.

**Day 3: UTC, policy and scan lifecycle**

- Go-compatible UTC midnight and timezone-offset boundaries.
- Agent > group > default policy precedence, platform scope, and
  reported-only ACK/revision interpretation.
- HTML/raw endpoint policy error suppression and explicit rejection
  of XML-bearing metadata response.
- Leased/queued job overdue at Go overview time; inverted/future
  timestamps, terminal lease contradictions and invalid server time.
- Scan path, request ID and active lease capability do not reach
  the derived lifecycle review object.

## Release acceptance gates NOT yet passed

| Gate | Evidence / status |
|---|---|
| Entire `frontend/`: `npm ci`, `npm run typecheck`, `npm test`, `npm run build` | **NOT EXECUTED** on exact full checkout. Isolated `tsc` cannot validate React/Vite deps, imports and all suites |
| Entire `backend/`: `go test ./...`, `go test -race ./...`, `go vet ./...` | **NOT EXECUTED** on complete repository. Only the exact standalone bearer helper and its 13 Go subtests were executed |
| Go HTTP handler integration, metadata redaction, TLS/cert enrollment, PostgreSQL 16 migrations | **NOT EXECUTED / UNVERIFIED**. Full-handler tests committed but require actual backend checkout/runner |
| Real Windows x64 and Linux Rust agent installation, ClamAV, Sysmon, telemetry source and response actions | **NOT EXECUTED** |
| Browser Chromium/Firefox, NVDA/Orca, keyboard/focus, 200% zoom, forced-colors, token/disconnect E2E | **NOT EXECUTED** |
| Agent 1 InfoSec and independent Agent 2 Backend / Agent 3 QA approvals | **NOT RECEIVED** |
| GitHub Actions exact-head verification | **BLOCKED** by zero-step runner-allocation failures in GitHub issues #153 and #148 |
| Release / deployment / merge | **NO-GO**, intentionally not performed |

### CI root-cause dependency

Backend and QA agree that prior runs across Go/Rust/React/PostgreSQL
failed with `runner_id=0`, `steps=[]` and no downloadable logs;
some check runs have an inaccessible annotation. Root cause is **not
confirmed**. The GitHub repository/account owner needs to inspect
one failed-run **job-start/check annotation**, repository/org Actions
policy, Actions usage/budget/billing/payment status, and runner
availability. See [issue #153](https://github.com/suhaylx/EDR/issues/153)
and [issue #148](https://github.com/suhaylx/EDR/issues/148).
Never disable tests or bypass authorizations to claim a pass.

### Backend/QA handoff

**Agent 2:** review bearer helper/compatibility, run the full Go
HTTP regression and full mTLS/PostgreSQL matrix on a trusted runner.
**Agent 3:** rerun the complete Frontend suite and actual browser/AT
checks, plus Windows/Linux E2E with all logs and exact commit.
**Agent 1:** approve reported-evidence semantics and authorization
threat model; **PM:** coordinate stacked draft PRs and release gates.

The three QA phases produced 31 genuine focused PASS results; the
**full three-day release QA remains blocked**, not passed.
