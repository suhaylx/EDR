# TuranSec Agent 5 — scan-evidence milestones M51–M75

**Status:** 25 focused, source-backed frontend acceptance checks on draft PR #114.
Not 25 production EDR releases or 25 separate native agent capabilities.
This branch is stacked on Agent 5 PR #100, then #76, #55 and the
integrated lab candidate #49. The only allowed private repository is
`suhaylx/EDR`; no merge, agent rollout, or server deployment is authorized
by this documentation.

The current laboratory Rust worker executes *path* scans only; quick and
full modes are not implemented. A successful-looking quick/full result is
an **unsupported claim**, even if sent in a malformed backend response.
The Go lab API should reject those results, and this frontend adds
defense-in-depth presentation checks. An accepted path scan report is not
cryptographic evidence that ClamAV ran, the signatures were fresh, or a file
was safe.

## 25 acceptance items and executable evidence

| ID | Read-only capability / safety acceptance | Automated test |
| --- | --- | --- |
| M51 | Reject claimed successful quick/full verdicts in UI | `scan-evidence-25.test.mjs` M51 |
| M52 | Quick/full error remains scanner error | M52 |
| M53 | Quick/full unscanned is not successful completion | M53 |
| M54 | Path malicious with named signature is reported only | M54 |
| M55 | Path suspicious is analyst evidence, not confirmed infection | M55 |
| M56 | Path signature-negative never means protected/safe | M56 |
| M57 | Completed delivery plus error remains scanner error | M57 |
| M58 | Completed delivery plus unscanned remains unscanned | M58 |
| M59 | Missing/unknown mode cannot count as path scan success | M59 |
| M60 | Positive verdict outside completed state is flagged | M60 |
| M61 | Malicious without signature name is insufficient evidence | M61 |
| M62 | Non-malicious with threat name is inconsistent | M62 |
| M63 | Missing engine/version/database are separate gaps | M63 |
| M64 | Missing timestamp and mode never attest freshness | M64 |
| M65 | Unknown statuses/verdicts stay unknown | M65 |
| M66 | Queued/leased pending filter | M66 |
| M67 | Failed/expired/error filter; unscanned independently | M67 |
| M68 | Unsupported quick/full claims isolated by filter | M68 |
| M69 | Path match/suspicious/signature-negative filters separate | M69 |
| M70 | Analyst attention identifies errors and metadata gaps | M70 |
| M71 | Exact endpoint ID filter, case insensitive | M71 |
| M72 | Case-insensitive returned-metadata search | M72 |
| M73 | Metadata completeness and scan-mode filters compose | M73 |
| M74 | UTC offset-aware sorting, missing dates last, source immutability | M74 |
| M75 | Bounded pagination, summary, API ID/control/text/date validation | M75 |

The UI in `frontend/src/ScanEvidenceWorkbench.tsx` uses
`scanEvidenceKind`, `scanEvidenceFlags`, `filterReportedScanJobs`,
`sortReportedScanJobs` and `paginateReportedScanJobs` for local-only
worklist presentation. The existing Go API is fetched by
`frontend/src/lab-api.ts` and validated before rendering. No write,
scan trigger, scan rerun, termination, quarantine, restore, disable,
network isolation or privileged endpoint action is present.

The UI provides native labeled controls, status-count live announcements,
per-job raw metadata disclosure, 25/50/100 row pagination, responsive
system light/dark/forced-color layouts and honest empty/error states.
`scan-evidence-render.test.mjs` adds server-rendered React semantic
markup, XSS-safe text, unsupported-claim labels and page-size checks.
These automated tests are **not** independent NVDA/Orca or browser
keyboard/zoom validation.

## Contract and trust limits

The reported scan job has `id`, `agent_id`, `status`, optional
`scan_type`, `verdict`, timestamps, engine/version, signature DB
version, threat name and worker detail. The decoder bounds string
length, rejects C0/DEL controls and duplicate IDs, and rejects malformed
nonempty creation timestamps. Fields missing from a pending job must not
be treated as successful scanner evidence. Authenticated endpoint
identity, production tenant isolation, replay-resistant commands,
signed policy attestations and a verified ClamAV DB freshness timestamp
are all **absent from this UI contract**. ClamAV version text is not
a verified age, hash or signature authenticity proof.

## Review and release gates

- **Agent 1 InfoSec:** approve category semantics and compare the UI
  against backend scan-capability restrictions and the outstanding
  draft scan-truth PR #53/#54. Ensure inconsistent reports are not
  promoted by another dashboard.
- **Agent 2 Backend:** provide an authenticated tenant/device-bound
  versioned scan job API with true execution provenance, durable
  retention, server paging, signature DB freshness, and audit trail.
  The present shared dev token is not production identity.
- **Agent 3 QA:** independently run Chromium/Firefox and Windows
  NVDA/Linux Orca, keyboard focus, 200% zoom, high contrast, dark/light,
  malicious long/multiline worker text, interrupted API results,
  stale token refresh, cross-tenant negative tests and actual Windows/
  Linux host E2E. Do not mark as run based on Node SSR alone.
- **Agent 4 PM:** reconcile stacked draft PR #114 → #100 → #76
  → #55/#49; run exact-head CI and review before any integration.
  Do not cherry-pick conflicting scan-file changes blindly.
- **Deployment:** none. All production security and QA gates remain
  blockers until separately reviewed and verified.
