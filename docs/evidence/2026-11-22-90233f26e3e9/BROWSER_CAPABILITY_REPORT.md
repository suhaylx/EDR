# Browser acceptance recovery: blocked by available execution surfaces

Candidate inspected: `fb0891f98919fd0a166ff10427088f195d208225`.
All tracked frontend blobs were materialized from that exact commit and independently checked against their Git blob hashes; see `source-verification.json`.
No repository implementation or GitHub state was changed.

## Observed supported surfaces

The CUA inventory exposed a running Chromium browser through its supported cloud automation API. Its documentation advertises UI/DOM interaction but no host/port forwarding or client-certificate browser-context configuration. The `cloud-shared-files` documentation exposes `/workspace/shared` for file exchange and specifically documents uploads and downloads; it does not advertise HTTP hosting.

A small synthetic HTML capability probe was created at `/workspace/shared/frontend-round2/probe.html`. It contained no repository code, credentials or project data. Opening its `file:` URL through the supported `createBrowserTab` API was explicitly rejected by the browser URL policy: only `http:` and `https:` protocols are allowed. The rejection prohibited attempting the same outcome through indirect execution, raw CDP, alternate browser surfaces or policy circumvention. No tab or test page opened. No such workaround was attempted.

The existing local execution evidence already records two independent limitations: Playwright's browser download returned HTTP 403, and installed Chromium failed before launch because its Unix socket creation was denied with EPERM. This investigation did not change sandbox or browser security settings, install trust roots, bypass a browser warning, or expose a local service publicly.

## Actual test evidence from this recovery attempt

- Exact candidate frontend source verification: PASS.
- `npm ci --offline --ignore-scripts`: PASS, package installation only.
- Actual React browser interactions: NOT EXECUTED.
- Keyboard acceptance: NOT EXECUTED.
- axe/WCAG checks: NOT EXECUTED.
- Browser authentication/unknown-state checks: NOT EXECUTED.
- Client-certificate/full TLS integration acceptance: NOT EXECUTED.
- Screenshots: none.

Previously passing unit/typecheck/build results are not reclassified as browser evidence. The existing certificate/health contradiction guard is present in the inspected source. No browser-observed implementation defect can be asserted because a page never loaded.

## Required capability to finish

Run the existing `npm run test:browser` harness on an authorized runner where Chromium can launch, or provide an approved HTTP(S) test origin reachable by a supported browser surface. The existing harness is a synthetic Node mTLS/frontend contract test; real Go/PostgreSQL/Rust and Windows/Linux host acceptance remain separate requirements even after it passes. Browser release acceptance must remain blocked until actual results exist.
