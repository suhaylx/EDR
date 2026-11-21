# TuranSec EDR — React operator SOC and local companion

**Scope:** The original React/TypeScript SOC and local companion are preserved at the explicit loopback `/lab/` route. The default `/` and `/soc/` routes provide an **authenticated operator SOC for endpoint inventory, path scans, reported results and detection case management** on the separate, same-origin HTTPS operator mTLS listener. The server, PostgreSQL registry, operator CA and browser certificate must be configured before it can connect. Rendering the UI or passing frontend tests does not establish endpoint protection, host acceptance or production readiness.

## Certificate-authenticated operator SOC

Build the reviewed candidate with the committed lockfile:

```bash
cd frontend
npm ci
npm run typecheck
npm test
npm run build
```

Use Node.js 22.12+ or 24. Set `EDR_SOC_UI_DIR` to the absolute path of the generated `frontend/dist` directory (or use the server configuration's `ui_dir` field). The Go operator service serves those built assets from its dedicated TLS listener and rejects `/lab/` and `/api/` there. Open the configured HTTPS operator URL and select the browser/OS-managed operator client certificate when prompted. Server trust, operator trust and endpoint agent trust are provisioned separately; the operator certificate must be enrolled for an enabled tenant with a `viewer` or `scanner` role. The UI does not import private keys, accept bearer tokens, or implement a shared server-side operator identity. See the candidate installation manual for the server environment and certificate provisioning commands.

Select **Connect to SOC**. The UI obtains `tenant_id`, `operator_id`, `role` and RFC3339 `server_time` from `GET /soc/v1/session`. A full refresh reads the authenticated tenant's endpoint inventory, endpoint counts, alerts, alert counts, current operator's active assigned cases, scan jobs, reported results and scan counts, then checks the session again. All eight data reads must succeed. Each list page is bounded to 25 rows, with a maximum offset of 10,000; pages and summaries are separate database reads and can change between requests.

Both roles can select **Read case and activity**, **Read scan details** or **Read result details**. A missing scan result is displayed as unknown, even if queue delivery is marked successful. The viewer role receives no write controls. Scanner-role operations use the existing backend routes below; every route is scoped under `/soc/v1/tenants/{tenant}/`.

| Workflow | UI and backend contract | Limits and resulting state |
| --- | --- | --- |
| Acknowledge | **Acknowledge** / `POST alerts/{id}/ack`, bodyless | Open → acknowledged; records triage only. |
| Resolve | **Resolution note**, **Resolve case** / `POST alerts/{id}/resolve`, `{note}` | Acknowledged → resolved; required single-line note ≤1,024 UTF-8 bytes. |
| Reopen | **Reopen case** / `POST alerts/{id}/reopen`, bodyless | Resolved → open. |
| Note | **Case note**, **Add note** / `POST alerts/{id}/notes`, `{note}` | Any case state; required single-line note ≤2,048 UTF-8 bytes. |
| Assign | **Scanner operator ID**, **Assign case** / `POST alerts/{id}/assign`, `{operator_id}` | Active cases only. The server verifies an active scanner in the same tenant. |
| Unassign | **Unassign case** / the same assignment route with explicit `{operator_id:""}` | Active assigned cases only; empty form submission is not an implicit unassign. |
| Queue path scan | **Endpoint to scan**, **Absolute local path**, **Queue path scan** / `POST scan-jobs`, `{agent_id,request_id,scan_root}` | One currently displayed, non-revoked endpoint; platform-valid local path ≤512 UTF-8 bytes; cryptographic UUIDv4 request key. A `201` creates work; a valid idempotent `200` identifies existing work. |
| Cancel pending scan | **Cancel pending scan** / `POST scan-jobs/{id}/cancel`, bodyless | Pending work only. The server also requires that the authenticated operator created that request; the read DTO does not expose its creator. Leased work cannot be cancelled here. |

Before each write, the client rechecks the current session and reloads the selected case, scan job or endpoint. Stale case state, assignment, revision, job state or changed identity aborts before dispatch. The server remains the authority for authentication, tenant scope, ownership and state transitions. These client checks are not atomic compare-and-swap semantics: another operator can change a record after the preflight read. The dedicated operator server's Origin and Sec-Fetch-Site checks remain required because client certificates are ambient browser credentials.

After a valid acceptance response, the UI reloads every snapshot source **and** the selected case/activity or job/result details. A failed reload retains only a bounded accepted-operation receipt and clears records. Network failure, timeout, cancellation or an unexpected response after POST is shown as **outcome unknown**, with instructions to reconnect and inspect current state. There is no automatic retry or optimistic counter/state change. Clearing a pending operation warns that it may already have been accepted; aborting the browser request does not undo a server write.

### Boundaries outside the implemented operator APIs

The authenticated service does not provide quick/full scan profiles, recurring scan schedules, endpoint isolation/quarantine, policy editing/deployment, an operator directory, certificate provisioning/revocation, or the original lab's investigation/telemetry views as tenant-authenticated SOC endpoints. This UI does not invent those operations or route them through the laboratory token API. Enrollment and certificate administration remain server/operator procedures. The local companion remains a read-only laboratory interface.

All requests use same-origin HTTPS credentials, `cache: no-store` and `redirect: error`. The browser negotiates the client certificate; no certificate key enters JavaScript. Each refresh clears the previous snapshot, accepts only bounded JSON fields, and verifies that the operator identity stayed the same throughout the request group. A network, authorization or schema failure clears displayed records. Clearing the view also cancels pending work and prevents late responses from repopulating it. **Clear displayed records** is not certificate revocation or TLS logout; the browser continues to manage that certificate.

An endpoint with no server heartbeat is **unseen**, a stale heartbeat remains **unknown** for current protection, and revoked enrollment is distinct from either. Scanner version and readiness are endpoint reports. A reported signature detection is not independently attested execution, and a resolved case does not prove remediation. No empty page or zero count is shown as a healthy fleet.

### Browser contract and accessibility checks

```bash
npm run build
./node_modules/.bin/playwright install --with-deps chromium
npm run test:browser
```

The harness uses the built React bundle, ephemeral synthetic certificates, a local Node HTTPS mTLS fixture and a separate loopback HTTP lab fixture. It is designed to check certificate-required transport, keyboard navigation, WCAG A/AA axe rules, authorization clearing, unknown/empty/mobile states, stale-request cancellation, scanner case forms, path request/cancellation, uncertain acknowledgement outcomes and the original companion's six-source read-only flow. Results and screenshots are written under `test-results/`. These checks are **frontend contract fixtures**, not the real Go/PostgreSQL/Rust integrated service or Windows/Linux host acceptance. They do not replace manual screen-reader evaluation or independent QA. A runner that cannot launch Chromium must report this gate as blocked, not passed.

The implementation workspace could run unit/contract tests, server-side React render assertions, type checking and the production build. It could not execute this browser harness: the browser download was denied and the installed local Chromium failed to create a Unix socket (`EPERM`). The available cloud browser permits HTTP(S) navigation only and rejected local file navigation by policy; no workaround was attempted. Therefore the updated browser scenarios, keyboard checks, axe checks and screenshots remain **UNEXECUTED** until an approved runner or supported test origin is available. Syntax checking the harness is not browser acceptance evidence.

## Local development (isolated loopback only)

Prerequisites: Node.js 22.12+ or 24, npm, a reviewed source tree and access to the npm registry; the matching Go lab API available on `127.0.0.1:8080` using `EDR_DEV_TOKEN`.

```bash
cd frontend
npm ci
npm run typecheck
npm test
npm run build
npm run dev
```

Open **`http://127.0.0.1:5173/lab/`**. The React/Vite development server listens on loopback and proxies `/api` to the locally running Go lab server. The default `/` route remains the operator SOC and refuses to send operator requests over HTTP. `/lab/` is unavailable on non-loopback hostnames. Do **not** expose either lab port publicly. Enter the **lab token** in the UI (not in a Vite environment variable). The token is held in React state and cleared by Disconnect or page close. A local JavaScript page or extension with DOM execution rights can read its input; this is **not a production authentication design**.

## Original loopback laboratory features

- React SOC overview with reconciled online/offline/unknown server heartbeat status, retained alert trends, severity, busiest observed endpoints, fired rules, scan job health and explicit unverified coverage gaps.
- On-demand React investigation by same-endpoint process GUID or retained detection ID; strict response provenance validation, observed/reported edge labels, process tree disclosure controls, source-ID links to retained timeline and explicit truncation/collection gaps. No inferred process causation.
- Selectable 1/7/30-day UTC reporting window; changing it discards old summaries until a matching new authenticated fetch succeeds. No fake live data and no endpoint actions.

- Strictly typed parsers for `GET /api/overview?days=1|7|30` and the metadata-only `GET /api/scan-job-metadata`, rejecting malformed or oversized responses and any scan `path`, `request_id`, `lease_id`, `threat_name` or `detail` field in the analyst feed; explicit empty/error/loading states.
- Reported scan statuses distinct from actual protection; real scan trust and signature DB freshness **not verified**.
- Reported signature presence is a boolean, not the private signature name. Scan paths, request IDs, active leases and raw worker details are withheld from the React analyst response, search and markup. No HTML injection or direct endpoint action.
- System light/dark CSS tokens, keyboard-visible focus, reduced-motion styles and responsive layout.
- Dev-only Vite `/api` proxy; the separate operator view calls the authenticated tenant API directly on its own HTTPS origin.

## Release blockers

The operator UI requires the complete reviewed candidate with its same-origin static handler and `/soc/v1/session`; earlier lab-only backend versions cannot satisfy that contract. Production additionally requires successful CI for the exact candidate commit, independent InfoSec/QA approvals, real Windows/Linux host acceptance, approved package signing, rollback evidence and explicit deployment authorization. No ClamAV/Sysmon protection is inferred from a rendered row. A standalone React app is not a separate endpoint **agent**.

## Detection-to-investigation lab navigation

The React Security alerts view reads `GET /api/detections` after connection and filters timestamps against the Go overview's generated timestamp and selected 1/7/30-day UTC calendar window. Each retained detection has a read-only **Investigate evidence** control that preselects its real `device_id` and detection `id`; the analyst explicitly submits the graph query. The lab heuristic is not confirmed malware, and a file-create ID must never be confused with a module-load event. The shared development token is not a tenant-safe production identity. Agent 3 must manually test this flow with real browser keyboard/screen reader and Agent 2 must review durable authenticated API provenance.

## Read-only enrolled endpoint inventory

The backend-aligned lab review also reads a metadata-only <code>GET /api/policy-metadata</code> response; Go exposes no XML through that route, and the React parser rejects XML-bearing fallback data. Reported policy errors are shown as a status only; sensitive endpoint error text is withheld. This remains a shared-token lab contract, not the separate mTLS SOC API.

The React Endpoints tab now reads `endpoints` from the existing server-generated `GET /api/overview?days=1|7|30` response, checks the total and online/offline/unknown counts for consistency, and displays server-received heartbeat status, inactivity, event/alert counts, and **unverified agent-reported** health and applied-policy acknowledgments. Analysts can filter by heartbeat and endpoint/group/policy, and sort locally by ID, observed events, or elapsed inactivity. Missing heartbeat status is **unknown**, never a fabricated offline duration. No response, policy mutation, or deployment controls are exposed. Server-side tenant scoping, signed health/policy evidence, real browser accessibility testing and durable inventory remain release blockers.

## Metadata-only scan listing (Agent 5 / Agent 2 QA review)

The React scan-history workbench now calls `GET /api/scan-job-metadata` with the development bearer token, using no-store and no cookies. The Go lab server converts queue entries to `ScanJobReview` *before* JSON serialization. Only job IDs, endpoint IDs, mode/state, lifecycle times, engine/version, verdict and `signature_reported` are returned. React refuses a legacy raw queue response. The older `GET /api/scan-jobs` remains available for legacy lab clients and still needs Agent 2/InfoSec authorization and migration review. Neither route is a production mTLS SOC API. Regression and manual-QA gates are recorded in `docs/qa/agent5-scan-metadata-second-review-20261121.md`; no scanner execution or production policy enforcement is attested.
