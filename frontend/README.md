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
- React-native text rendering for untrusted worker details; no HTML injection, no direct endpoint action.
- System light/dark CSS tokens, keyboard-visible focus, reduced-motion styles and responsive layout.
- Dev-only Vite proxy; no production server migration or authenticated multi-tenant API.

## Release blockers

This app has not replaced `backend/web`; the Go `http.FileServer` still serves the original JS lab UI. Production requires Agent 2 secure session/mTLS/device and tenant-scoped Go APIs, durable scan history, validated provenance and packaging. Agent 3 must perform real browser accessibility/security QA and live Windows/Linux lab integration tests. No ClamAV/Sysmon protection is inferred from a rendered row. A standalone React app is not a separate endpoint **agent**.
