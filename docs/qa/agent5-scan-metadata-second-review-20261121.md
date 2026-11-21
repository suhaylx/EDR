# Agent 5 — Second Frontend / Backend / QA Review (Scan Metadata)

**Review date:** 2026-11-21 (Asia/Tashkent). Repository: private
`suhaylx/EDR` only. Stacked on draft review PR #158 → sprint PR #151.
This is a **read-only laboratory API remediation**, not a production
tenant-authorization, scan execution, native-agent, or deployment change.

## Source-level finding and fix (P1: unnecessary data disclosure)

**Prior behavior:** Go `GET /api/scan-jobs` marshaled the full
`ScanJob` struct with sensitive fields `path`, `request_id`,
`threat_name` and untrusted `detail`; the server strips `lease_id`
in the listing, but the browser still received scan path and worker
metadata it did not need. React `decodeScanJobs` dropped path and
request IDs after downloading, while `ScanEvidenceWorkbench` rendered
the threat name and raw worker details. Local scan text search indexed
the same sensitive fields. An authenticated lab-token user could
therefore see unnecessary raw evidence in the network response, DOM,
and search. This is **not a demonstrated production incident**:
the Go API is a dev-only bearer-token lab and separate from Agent 2's
unmerged SOC mTLS server APIs.

**Remediation:** Add `GET /api/scan-job-metadata` to the existing
lab handler. Go `ScanJobReview` DTO includes only ID, endpoint ID,
state, mode, lifecycle timestamps, reported engine/version/database,
verdict and a `signature_reported` boolean. It omits scan path,
request ID, active lease capability, signature name and raw worker
detail **before serialization**. The legacy `/api/scan-jobs` remains
for existing lab clients and still has path/request fields: a wider
API-authorization and migration decision requires Agent 2/InfoSec.

The React `fetchLabScanJobs` uses only the new metadata-only route.
A strict `decodeLabScanReviewJobs` rejects missing/invalid signature
indicators and any forbidden legacy fields, including fields present
with `null`. The existing `decodeScanJobs` remains available for
legacy unit fixtures and deliberately projects only known fields.
`ScanJob` has optional `signature_reported`; the scan workbench
uses it to preserve **reported match, not attested** classifications.
It never prints raw signature names or worker messages, even when
a legacy object is supplied directly to the component. Local job
search excludes signature and worker-detail text. No scan command,
lease acquisition, retry, quarantine or endpoint action is added.

## QA / Backend acceptance

Agent 2 backend review must validate:
- Go source `backend/internal/edr/scan_job_metadata.go` and new
  GET handler path in `backend/internal/edr/http.go` are
  read-only; cache-control no-store and bearer auth preserved.
- New route JSON must exclude `request_id`, `path`, `lease_id`,
  `threat_name`, `detail`; `signature_reported` always boolean,
  and timestamps match the original Go source without inventing
  scan execution.
- Existing `/api/scan-jobs` remains compatibility-only; confirm
  whether it should be retired, narrowed or authorized with
  per-agent mTLS. This PR does **not** harden the legacy route.
- `signature_reported=true` is metadata-only and never a signed
  ClamAV rule/DB attest. Do not connect to production mTLS SOC APIs
  without a separate browser/operator authorization design.

Agent 3 independent QA checks:
- `backend/internal/edr/scan_job_metadata_test.go`: redaction,
  401/no-store, POST forbidden and no queue mutation.
- `frontend/tests/lab-api.test.mjs`, `scan-metadata-contract.test.mjs`,
  `scan-state.test.mjs`, `scan-evidence-25.test.mjs`,
  `scan-evidence-render.test.mjs`: strict response shapes,
  signature boolean and warning precedence, private-field refusal,
  no worker text in HTML or text search, negative bearer token.
- Real browser Chromium/Firefox Tab/Enter, 200% zoom,
  contrast and NVDA/Orca where available, plus six-request
  failure and token-rotation tests. SSR unit checks are **not**
  assistive technology evidence.

```sh
cd backend
go test ./internal/edr -run 'Test(PolicyMetadata|ScanJobMetadata)' -count=1 -v
go test ./...
go vet ./...
cd ../frontend
npm ci
npm run typecheck
npm test
npm run build
```

**Verification status:** Committed tests are **NOT PASSED until exact
head logs exist**. GitHub Actions has been failing with zero
runner steps and `BlobNotFound` 404 in unrelated workflows; see
[DevOps #153](https://github.com/suhaylx/EDR/issues/153)
and [QA #148](https://github.com/suhaylx/EDR/issues/148).
No temporary third-party CI runner, disabling security checks,
unreviewed merging, or production deployment is permitted.

**Review ownership:** Agent 2 must approve Go API change/compatibility;
Agent 3 must independently execute tests and browser QA;
Agent 1 must approve information-disclosure boundaries; PM
must reconcile stacked draft PRs before integration. Currently
release decision is **NO-GO**.
