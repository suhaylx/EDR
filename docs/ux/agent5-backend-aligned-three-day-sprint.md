# Agent 5 — backend-aligned three-day Frontend sprint

**Sprint executed as three sequential engineering increments on 2026-11-21
(Asia/Tashkent), not as three elapsed days or three production deployments.**
Private authorized repository: `suhaylx/EDR` only. Branch:
`feat/agent5-backend-aligned-3day-sprint-20261121`.
Stacked on draft frontend PR #140 → #131 → #124 → #114 → #100 → #76
→ #55/#49. Do **not** merge or deploy without Agent 1/2/3/PM gates.

## Actual Go backend inspection / source of truth

- `backend/internal/edr/overview.go`: `BuildSOCOverview` uses
  `now.UTC().Truncate(24*time.Hour).AddDate(0,0,-(days-1))`.
  Valid days: 1, 7, 30. Events are filtered on **Event.Time**,
  not `ReceivedAt`; detections on `ObservedAt`; scan jobs on
  `CreatedAt`. The Go overview is a separate in-memory request and
  **not atomic** with `GET /api/events` (last 100), `/api/detections`
  (all retained), `/api/scan-jobs` (all returned jobs), `/api/policies`
  or `/api/assignments`.
- `backend/internal/edr/http.go`: GET-only lab endpoints exist for
  `/api/overview?days=1|7|30`, `/api/events`, `/api/detections`,
  `/api/scan-jobs`, `/api/policies`, `/api/assignments`,
  `/api/investigations`; they are guarded by **one shared development
  bearer token**. Policy mutation and scan job POST endpoints exist
  but are never invoked by this frontend sprint.
- `backend/internal/edr/store.go`: Policy fields `id,name,platform,
  revision,xml,sha256,created_at` and assignment fields `target_type,
  target_id,platform,policy_id`. Desired precedence per platform is
  **agent → group → default**. Agent `applied_policy_id`,
  `applied_revision`, `last_policy_error` are reported acknowledgment
  fields, not verified Sysmon policy enforcement.
- `backend/internal/edr/scans.go`: Scan job fields include `id,
  request_id,agent_id,scan_type,path,status,created_at,expires_at,
  lease_until,lease_id,completed_at,engine,engine_version,
  database_version,verdict,threat_name,detail`. The GET list strips
  active `lease_id`; state transitions depend on lease delivery,
  and even successful-looking completions are **not scanner
  attestations**. The Rust lab worker does **not** implement quick/full
  scans; successful claims for those are rejected by Go.

## Day 1 — UTC contract reconciliation

**Implementation:** `frontend/src/backend-utc-window.ts` implements Go's
UTC calendar-midnight boundary; `detections.ts` uses it instead of
rolling N*24-hour windows, and absolute UTC milliseconds for sorting
time-zone-offset observations. `evidence-snapshot.ts` now uses the
same calendar cutoff and **Event.Time** (not Go `received_at`) for
backend-count-comparable retained event windows. Receipt and sender
time remain independently visible as unverified provenance, including
future-time warnings. The former assumption created near-midnight
false discrepancies. Existing M127 acceptance was corrected.
**Tests:** `backend-calendar-window.test.mjs`, M127; midnight,
1/7/30-day ranges, offset zones, future exclusion, type failure.

## Day 2 — policy intention vs reported acknowledgments

**Implementation:** `policy-readonly.ts` decodes bounded policy
metadata and assignment IDs from **GET** only; checks policy revision,
date, digest and duplicate IDs; intentionally **does not retain or
display raw Sysmon XML**, even though the Go GET policy object includes it.
It computes actual server precedence agent > group > default and
compares intended ID/revision to endpoint acknowledgments.
`PolicyEvidenceReview.tsx` adds a read-only dashboard tab with
accessible filters and 25/50/100 paging. Reported errors, unassigned
devices, unknown policies, mismatch/awaiting-ack and matching **reported**
revision are distinguished. No policy write/rollback/disable control.
`main.tsx` fetches **all six** read-only endpoints as one
all-or-nothing client refresh; token edit, disconnect, failure or
UTC window change clears policy evidence too.
**Tests:** `policy-backend-contract.test.mjs`, SSR regression
`backend-aligned-sprint-render.test.mjs`.

## Day 3 — scan job lifecycle without false scan success

**Implementation:** `lab-api.ts` decodes Go `expires_at`,
`lease_until`, `completed_at` with timestamp bounds; deliberately
drops `lease_id`, `request_id`, and `path` from React state.
`scan-lifecycle.ts` reviews queued/leased jobs beyond reported
expiry, missing terminal completion, inverted timestamps,
lease-after-expiry, terminal lease leakage and future clocks against
**Go overview generated_at** (not analyst local time).
`ScanLifecycleReview.tsx` provides read-only table, aggregate
warnings and 25-row pagination alongside scan worklist. It does
**not** claim a scan executed, or offer lease, scan/kill, quarantine
or host isolation actions.
**Tests:** `backend-scan-lifecycle.test.mjs`, SSR
`backend-aligned-sprint-render.test.mjs`.

## Release evidence and unresolved requirements

- `frontend/package.json`: typed module compilation, all
  `tests/*.test.mjs`, strict TypeScript and Vite build.
- `frontend/src/styles.css`: mobile/large screen, system light/dark,
  focus-visible, forced-colors responsive presentations.
- **Exact-head CI must be checked** on this feature branch.
  Prior PR #140 Actions workflows failed without runner steps and
  unavailable log blobs, so do not imply success from code alone.
- **Agent 1 InfoSec:** semantics of event clocks, policy errors,
  lease/scan states and privacy; threat-review signoff.
- **Agent 2 Backend:** authenticated tenant/device mTLS,
  durable server queue, immutable audit, trusted source clocks,
  signed desired-policy commands, verified Sysmon policy application,
  real scan capabilities and durable paginated snapshot APIs.
  Current dev bearer token cannot satisfy these.
- **Agent 3 QA:** independent Chromium/Firefox keyboard, NVDA/Orca,
  200% zoom, dark/light/forced-colors, token rotation/401,
  malformed JSON/XML, clock-skew, scan expiry, Windows/Linux lab
  validation and deployment/rollback tests. Node SSR tests are
  not manual assistive-technology evidence.
- **PM:** reconcile and review the dependent draft PR chain; do
  not merge or deploy to endpoints without signed build,
  InfoSec/QA, staging canary and rollback evidence.
- **Production deployment:** none; local React laboratory
  evaluation UI is separate from the shipped Go-served web app.

## Engineering verification commands (frontend directory)

```bash
npm ci
npm run typecheck
npm test
npm run build
```

The presence of these commands is not evidence they ran.
Record exact head SHA and workflow conclusions after execution.
