# Agent 5 — M126–M150: SOC Evidence Snapshot Review

**Status:** review-only React/TypeScript laboratory UX. Source: private `suhaylx/EDR` only. Stacked on draft PR #131 → #124 → #114 → #100 → #76 → #55/#49. These are **25 code-backed frontend acceptance items**, not 25 production deployments or attested EDR capabilities.

## Delivered experience

The new **Evidence snapshot** tab is available only after the existing
`Promise.all` refresh receives and validates **all four** read-only Go
development responses: `/api/overview`, `/api/scan-jobs`,
`/api/detections` and `/api/events`. The tab displays no prior
or partial evidence while disconnected, loading, or after a failed
request; existing token edits, disconnect and UTC-window changes
also invalidate the current data. No additional API polling,
write operation, or endpoint command is added.

`frontend/src/evidence-snapshot.ts` derives:
- A reported Go server overview timestamp and 1/7/30-day
  **inclusive UTC window**; it never uses the browser wall clock
  to decide which records count as within the window.
- Distinct **overview-reported** alert/event counts and
  **separately returned samples**. The event API returns at
  most 100 recent records, while detections, scan jobs and
  the overview have different limits; counts are not directly
  comparable or proof of event loss, complete collection,
  policy coverage or a clean endpoint.
- Telemetry event time chosen from Go receipt time if available,
  else sender time (explicitly labeled as untrusted), else
  unknown. Future timestamps relative to overview generation
  are flagged as possible clock/request timing differences,
  **not verified manipulation**.
- Windows Sysmon reports, Linux reports and other reports
  distinctly. All observed Sysmon IDs can be displayed by
  numeric class, including 7 ImageLoad, 11 FileCreate,
  24 clipboard metadata and 255 error. Observed IDs are not
  installed Sysmon configuration or requested policy coverage.
  **No clipboard detail, raw source body, credentials or
  worker detail is copied to summary rollups/search.**
- An overview-inventory-only endpoint table, joined by
  **exact opaque ID** (not fuzzy hostname normalization or
  cross-host process GUID). It counts the returned in-window
  alerts/events and **all returned scan jobs** separately;
  scan jobs do not falsely inherit the overview's UTC period.
- Missing inventory references are noted as unverified data
  discrepancies, not cross-tenant findings; quick/full
  success claims remain unsupported by the current Rust
  path-only lab worker.

`frontend/src/EvidenceSnapshotReview.tsx` renders the information
with responsive tables, a returned-source summary, a Sysmon
ID disclosure, source-clock warnings, exact field labels,
live result count, heartbeat/search/sort filters, and bounded
25/50/100-row paging. React escapes untrusted endpoint text
and no privileged actions exist.

## Named acceptance tests (M126–M150)

Tests are in `frontend/tests/evidence-snapshot-25.test.mjs`.

| ID | Verified behavior |
| --- | --- |
| M126 | Use the reported Go overview UTC generation time |
| M127 | 1/7-day inclusivity at exact UTC window boundaries |
| M128 | Reject malformed/unrecognized UTC window reference |
| M129 | Separate in-window and out-of-window detection samples |
| M130 | Future-dated detections excluded and warned |
| M131 | Offset timestamps compared as UTC instants |
| M132 | Go receipt clock preferred over sender clock |
| M133 | Explicit sender-clock fallback |
| M134 | Both missing clocks remain unknown, not zero-time |
| M135 | Empty event samples never establish complete coverage |
| M136 | Exactly 100 records trigger sample-limit warning |
| M137 | 99 records do not claim to reach the sample limit |
| M138 | Non-Sysmon Windows records classified as Other |
| M139 | Numeric Sysmon 7 vs 11 separately counted |
| M140 | Linux records cannot imply Windows Sysmon coverage |
| M141 | Sysmon 24 clipboard content withheld from summary |
| M142 | Windows Sysmon/Linux/Other event counts partition window |
| M143 | Future event receipt flagged, not called lost data |
| M144 | Returned evidence joined to exact enrolled endpoint ID |
| M145 | Case-varied endpoint IDs do not silently merge |
| M146 | Unlisted reported endpoint ID is not called tenant breach |
| M147 | Scan-job response counts never inherit alert UTC filter |
| M148 | Unsupported quick/full claimed successes identified |
| M149 | Signature-negative/unscanned/unknown states remain distinct |
| M150 | Local filters, stable sort, 25/50/100 paging, bad-page rejection |

`frontend/tests/evidence-snapshot-render.test.mjs` adds
rendered React tests for labels, ARIA status, captions,
empty-coverage caveats, XSS-safe text, clipboard privacy,
25-row paging and separate Event 7/Event 11 descriptions.
Strict CI also runs `tsc --noEmit` and Vite build.

## Review/release dependencies

**Agent 1 / InfoSec:** review all clock, Sysmon and scan-claim
semantics. **Agent 2 / Backend:** eventually provide an
authenticated tenant-scoped, paginated and versioned **atomic
or snapshot-consistent** evidence API with source provenance
and verified policy/scan information. Current in-memory lab
bearer-token endpoints do not provide this. **Agent 3 / QA:**
perform real browser keyboard/Tab, screen-reader NVDA/Orca,
200% zoom, dark/light, forced colors, malformed long data,
cross-host mismatches, token/disconnect/refresh overlap,
Windows/Linux native tests. Node SSR tests are not equivalent
to those manual tests. **PM:** reconcile stacked draft PRs
and obtain all approvals and exact-head CI before merge.
No merge, release, production installation, or deployment is
authorized or represented by this branch.
