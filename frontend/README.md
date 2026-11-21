# TuranSec EDR — React SOC lab slice

**Scope:** A separate, **read-only** React/TypeScript SOC overview, scan-history and investigation application. This is not the live dashboard served by Go yet and is **not production EDR**. The original Go-served JavaScript SOC console remains at `http://127.0.0.1:8080/` and is unchanged.

## Local development (isolated loopback only)

Prerequisites: Node.js 22+, npm, a reviewed source tree and access to the npm registry; Go lab API available on `127.0.0.1:8080` using `EDR_DEV_TOKEN`.

```bash
cd frontend
npm install
npm run typecheck
npm test
npm run build
npm run dev
```

The React/Vite development server listens on `127.0.0.1:5173`; it proxies `/api` to the locally running Go lab server. Do **not** expose either port publicly. Enter the **lab token** in the UI (not in a Vite environment variable). The token is held in React state and cleared by Disconnect or page close. A local JavaScript page or extension with DOM execution rights can read its input; this is **not a production authentication design**.

## Implemented in this slice

- React SOC overview with reconciled online/offline/unknown server heartbeat status, retained alert trends, severity, busiest observed endpoints, fired rules, scan job health and explicit unverified coverage gaps.
- On-demand React investigation by same-endpoint process GUID or retained detection ID; strict response provenance validation, observed/reported edge labels, process tree disclosure controls, source-ID links to retained timeline and explicit truncation/collection gaps. No inferred process causation.
- Selectable 1/7/30-day UTC reporting window; changing it discards old summaries until a matching new authenticated fetch succeeds. No fake live data and no endpoint actions.

- Strictly typed parsers for `GET /api/overview?days=1|7|30` and `GET /api/scan-jobs`, rejecting malformed or oversized responses; explicit empty/error/loading states.
- Reported scan statuses distinct from actual protection; real scan trust and signature DB freshness **not verified**.
- Scan-history read-only, keyboard-labeled local filters for queued/leased, failed/expired/error, unscanned, completed reported signature match, completed signature-negative and unrecognized/malformed results; metadata search is in memory only and does not request more endpoint work. Counts refer to returned records only, with no fleet-completeness inference.
- React-native text rendering for untrusted worker details; no HTML injection, no direct endpoint action.
- System light/dark CSS tokens, keyboard-visible focus, reduced-motion styles and responsive layout.
- Dev-only Vite proxy; no production server migration or authenticated multi-tenant API.

## Release blockers

This app has not replaced `backend/web`; the Go `http.FileServer` still serves the original JS lab UI. Production requires Agent 2 secure session/mTLS/device and tenant-scoped Go APIs, durable scan history, validated provenance and packaging. Agent 3 must perform real browser accessibility/security QA and live Windows/Linux lab integration tests. No ClamAV/Sysmon protection is inferred from a rendered row. A standalone React app is not a separate endpoint **agent**.

## Detection-to-investigation lab navigation

The React Security alerts view reads `GET /api/detections` after connection and filters timestamps against the Go overview's generated timestamp and selected 1/7/30-day rolling window. Each retained detection has a read-only **Investigate evidence** control that preselects its real `device_id` and detection `id`; the analyst explicitly submits the graph query. The lab heuristic is not confirmed malware, and a file-create ID must never be confused with a module-load event. The shared development token is not a tenant-safe production identity. Agent 3 must manually test this flow with real browser keyboard/screen reader and Agent 2 must review durable authenticated API provenance.

## Read-only enrolled endpoint inventory

The React Endpoints tab now reads `endpoints` from the existing server-generated `GET /api/overview?days=1|7|30` response, checks the total and online/offline/unknown counts for consistency, and displays server-received heartbeat status, inactivity, event/alert counts, and **unverified agent-reported** health and applied-policy acknowledgments. Analysts can filter by heartbeat and endpoint/group/policy, and sort locally by ID, observed events, or elapsed inactivity. Missing heartbeat status is **unknown**, never a fabricated offline duration. No response, policy mutation, or deployment controls are exposed. Server-side tenant scoping, signed health/policy evidence, real browser accessibility testing and durable inventory remain release blockers.


## Policy acknowledgement evidence (Agent 5 increment)

The **Policy evidence** React view consumes only the existing, validated `GET /api/overview?days=1|7|30` fields: `policy_coverage`, `policy_errors`, and the `endpoints[].applied_policy_id`, `applied_revision`, `last_policy_error`, `status` records. The day selector limits *activity* aggregates; policy acknowledgements are a point-in-time snapshot (`generated_at`). The view does not write to Go APIs or Rust agent policy.

`src/policy-evidence.ts` compares API aggregate counts with agent-reported IDs from the same overview response, exposes missing policy acknowledgements, endpoint-reported errors and stale/unknown heartbeat, and warns when summaries disagree. Exact duplicate-policy ID and empty-ID cases are shown as consistency warnings instead of fabricated enforcement. Both matching counts and reported policy revision remain **unverified** for actual Sysmon installation, configuration, collector health, last-enforced hash, command authorization, and protection.

`src/PolicyEvidenceView.tsx` uses landmark headings, semantic read-only tables, text status labels and existing responsive light/dark styles; it has no inert rollout or policy-edit controls. `tests/policy-evidence.test.mjs` covers empty, stale, mismatched/duplicate and error states. Manual keyboard, screen reader, zoom and WCAG contrast verification still require Agent 3 on real browsers.

**Agent 2 contract gap:** production needs authenticated tenant-scoped desired/applied signed policy hashes, source/issued/acknowledged timestamps, Sysmon Event 1/7/11 and Linux collector coverage, policy validation errors, staging/rollback audit, strict pagination and data freshness. Version and authorize these server-side. **Agent 3 QA gap:** verify backend count semantics, untrusted policy names/errors XSS, keyboard focus and AT announcements, offline/unknown states and empty fleets against a real Go+Rust lab. There is no Windows tray/Linux companion IPC or protection attestation implemented here.

### Local policy evidence triage (Agent 5)

Policy evidence supports in-memory attention/error/missing-ID/offline/unknown filters and case-insensitive search, sorted with reported errors first. An applied policy ID with revision `0` is flagged as **absent or zero revision evidence**, not automatically a policy mismatch: the lab API defaults missing revision to zero and does not expose the desired policy revision, signed agent acknowledgements, or enforcement attestations. Local filter counts never change server claims or send commands. Manual keyboard/assistive-technology validation is still required.

## Local companion browser status-window prototype

`local-companion.html` is a second Vite page built alongside the SOC lab app (open
`http://127.0.0.1:5173/local-companion.html` after `npm run dev`). It renders
`src/LocalCompanionView.tsx` using the shared design tokens and responsive
`src/local-companion.css`. The bundled entry `src/local-companion-main.tsx`
always passes `snapshot={null}`: **no IPC, local agent, or privileged endpoint
service is connected**, and the interface cannot assert that any component is
healthy. There are no mock endpoint-action buttons.

`src/local-companion.ts` can format a candidate, separately authenticated
local status snapshot for a future trusted native host. Reported states explicitly
do **not** attest protection, scan verdict or Sysmon/collector coverage.
Missing/stale/future-dated reports reset all component rows to **Unknown** and
never retain a positive-looking state. Linux uses a Linux telemetry label rather
than Sysmon. Completed scan-job status has **no verdict** in this proposed v1
contract. The page is a browser **UX prototype**, not a Windows tray app, Linux
desktop bundle, native IPC host, single-binary agent, or deployed product.

Agent 2 must approve and implement authenticated, authorized local transport;
Agent 3 must run real browser/AT + platform testing and confirm any future
companion remains unprivileged and crash-isolated from Rust before release.
