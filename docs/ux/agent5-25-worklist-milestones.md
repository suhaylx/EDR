# Agent 5 — 25 SOC worklist/evidence acceptance checkpoints

**Scope:** 25 discrete, code-backed *laboratory frontend* acceptance checks,
not 25 production releases or 25 independent deployed agents. Implemented
on dependent draft PR #100, based on PR #76 and integration PR #55/#49.
The 25 named checks below are executable Node tests. No backend
actions, production rollout, or native tray/IPC work is claimed.

| Item | Acceptance behavior | Source / executable check |
| --- | --- | --- |
| M01 | Exact endpoint filter, case-insensitive, not partial | `analyst-worklist.ts` / `analyst-worklist.test.mjs` M01 |
| M02 | Exact detection rule ID | Same / M02 |
| M03 | Exact reported category | Same / M03 |
| M04 | Exact reported confidence | Same / M04 |
| M05 | Process GUID present/absent separation | Same / M05 |
| M06 | Separately linked FileCreate ID present/absent | Same / M06 |
| M07 | Reported target object present/absent | Same / M07 |
| M08 | Source found in current returned event sample (both host + Go ID) | Same / M08 |
| M09 | Matching Go event ID on another endpoint does not count as source | Same / M09 |
| M10 | Newest sort compares actual timestamps, including timezone offsets | Same / M10 |
| M11 | Oldest sort follows actual observation time | Same / M11 |
| M12 | Severity sort keeps unknown labels unclassified, after known bands | Same / M12 |
| M13 | Deterministic endpoint sort | Same / M13 |
| M14 | Deterministic rule sort | Same / M14 |
| M15 | Reported confidence sort, without verifying threat confidence | Same / M15 |
| M16 | Local 25/50/100 page sizes | Same / M16 |
| M17 | Previous/next page slices do not duplicate or skip records | Same / M17 |
| M18 | Out-of-range page clamping; invalid parameters fail closed | Same / M18 |
| M19 | API rows are not mutated by sorting/filtering | Same / M19 |
| M20 | Exact filters compose rather than broadening results | Same / M20 |
| M21 | Gap summary differentiates absent metadata and sample membership | `evidence-gaps.ts` / `evidence-gaps.test.mjs` M21 |
| M22 | Separate FileCreate reference never duplicates primary and expects ID 11 | `multisignal-alert-triage.ts` / `evidence-gaps.test.mjs` M22 |
| M23 | Co-observed process context requires same endpoint + GUID | `evidence-gaps.ts` / `evidence-gaps.test.mjs` M23 |
| M24 | Related context is bounded to 10 displayed records, never a full history | Same / M24 |
| M25 | Different-host same event ID does not count as returned-source evidence | Same / M25 |

## UI wiring and additional rendering tests

- `MultisignalAlertTriage.tsx` adds advanced filters, sort selector,
  25/50/100 page-size selector, Previous/Next, Clear, local evidence gap
  counts, linked FileCreate source inspection and live visible count.
  Changing a filter or sort resets the page to the first page.
- `RetainedSourceInspection.tsx` focuses its heading, warns when a
  claimed FileCreate ID resolves to a non-11 event, and lists up to
  10 other returned events with the same reported host and GUID,
  **not inferred causal/parent-child edges**.
- `SysmonCoverage.tsx` links each returned Go event ID to that
  same-host read-only inspection view, with an accessible button label.
- `frontend/tests/agent5-worklist-render.test.mjs` checks native
  labels, table paging, FileCreate warning, co-observed context,
  direct event navigation and React-escaped untrusted content.
- `frontend/src/styles.css` adds mobile, forced-color, and
  focus-visible styling. `docs/ux/design-system.md` records
  platform principles and manual QA gates.

## Evidence language and review restrictions

A source **not in the last 100 returned events** is not an event that
never happened. A listed FileCreate reference is not verified Sysmon
Event 11, and never proves DLL execution. A matching host+GUID
is not evidence of parentage, attack chain or confirmed incident.
All counts are lab API response-scoped. This React app cannot
authorize endpoint control actions or bypass the Rust policy core.

**CI status:** Record exact final SHA, frontend TypeScript/test/Vite
runs and relevant Go/Rust/Windows workflows on PR #100 after
they complete. Initial head CI caught an incorrect SSR test
expectation (total matched vs current-page rows); a test-only
correction was committed. No new HEAD success is claimed in
this document.

**Agent 2:** approve source identity/schema, signed and tenant
scoping, durable pagination. **Agent 1:** detection semantics and
what counts as observable evidence. **Agent 3:** keyboard, NVDA,
Orca, 200% zoom, forced colors, XSS, origin/credential handling
and live Windows/Linux lab tests. **PM:** reconcile stacked drafts
before any merge. No release gates are waived.
