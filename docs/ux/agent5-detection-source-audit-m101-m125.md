# Agent 5 — M101–M125 Detection Source Integrity Audit

**Status:** review-only React/TypeScript lab improvement in the sole authorized
private repository `suhaylx/EDR`. This is a 25-item automated acceptance
batch, not 25 independent production releases. Stacked on Agent 5 PR #124,
then #114, #100, #76, telemetry PR #55 and integration PR #49.
No main merge, production deployment or new backend privilege.

## Implemented UX

A disclosure in **Security Alerts** opens the
`DetectionSourceAudit` workbench. This computes discrepancies between
retained `GET /api/detections` and the **current at-most-100** records
from `GET /api/events`. Each claimed Go event ID is matched by both its
**exact opaque endpoint ID** and **Go event ID**, never by Windows
`source_record_id`, partial hostname, case-folded identity, or process
GUID alone.

For each returned alert, distinguish:
- Primary source ID absent/not retained; reported Windows Sysmon event
  type agreement, conflict, or unreported type.
- Both nonempty process GUIDs disagree; missing GUID is uncertainty,
  **not** parentage evidence or a valid negative match.
- FileCreate reference absent, duplicate primary reference, missing
  in sample, wrong type, or reported Sysmon Event ID **11**.
  FileCreate 11 is separate from image load 7 and does **not**
  establish DLL execution.
- Source receipt time missing or later than overview generation.
  Time comparisons are only consistency flags, not authenticated
  clocks or event-order/causality verification.
- No raw source field, sender detail or clipboard data (Sysmon
  Event ID 24) is copied to the audit rows or local search.

The workbench includes response-scoped counters, exact-host search,
severity and discrepancy filters, stable warning-first sorting,
25/50/100 local pages, live result counts, accessible labels and
React-escaped evidence. Source inspection buttons appear only for
records **actually found on that reported host**; the detection
itself remains available for read-only investigation. No scan,
quarantine, network isolation, command, incident-close or policy
mutation is offered. Reported type agreement **is not an attestation**.

## Acceptance checklist

All tests are named in `frontend/tests/detection-source-audit-25.test.mjs`.

| Milestone | Testable acceptance |
| --- | --- |
| M101 | Exact reported Go source ID plus host correlation |
| M102 | Cross-host same-ID collision rejected |
| M103 | Event ID capitalization not silently normalized |
| M104 | Legacy load-event fallback only if primary absent |
| M105 | Missing primary reference remains unknown |
| M106 | Not retained in sample is not asserted event loss |
| M107 | Reported Sysmon type agreement is labeled not attested |
| M108 | Numeric Sysmon type disagreement flagged |
| M109 | Detection numeric type zero remains unknown |
| M110 | Source numeric type zero remains untyped |
| M111 | Linux collector does not certify Windows Sysmon |
| M112 | Conflicting nonempty GUIDs are distinguishable |
| M113 | Missing detection GUID is unknown |
| M114 | Missing source GUID is not a mismatch |
| M115 | Separate reported Sysmon 11 FileCreate link |
| M116 | Unretained linked FileCreate source |
| M117 | ImageLoad 7 cannot count as FileCreate 11 |
| M118 | Linked ID equal to primary is not separate evidence |
| M119 | Cross-host FileCreate collision rejected |
| M120 | Missing server-received clock is explicitly unknown |
| M121 | Receipt later than overview generation warned |
| M122 | Clipboard details absent from audit and search |
| M123 | Exact host and other/unclassified severity filters |
| M124 | Deterministic warning/severity/rule sort, no mutation |
| M125 | Bounded 25/50/100 paging; duplicate source identity fails closed |

Additional `detection-source-audit-render.test.mjs` checks native
labels, captions, live counts, disclosure integration, XSS-safe
React rendering, page bounds, clipboard privacy, empty states
and absence of endpoint response controls. `frontend/package.json`
compiles both modules in strict typed CI; `styles.css` adds
responsive system light/dark/forced-color and keyboard-visible
focus states.

## Non-negotiable boundaries and reviewers

- **Agent 1 / InfoSec:** approve source-type/GUID semantics,
  sample gap wording, false-positive and privacy behavior.
- **Agent 2 / Backend:** implement authenticated tenant/device
  provenance, source-level signature or trusted collector
  attestations, durable pagination and consistent clock semantics
  before production correlation; the current shared lab bearer
  token and in-memory APIs cannot attest source integrity.
- **Agent 3 / QA:** run real browser keyboard, NVDA/Orca,
  high contrast, dark/light mode, 200% zoom, malicious metadata,
  cross-host collisions, forced-color and native Windows/Linux
  tests. SSR/Node tests do **not** constitute such QA.
- **PM:** reconcile stacked PRs and scan fix PR #53/#54 with
  review and exact-head CI before merging. No deployment.

CI status must be grounded in exact-head workflow conclusions,
not inferred from this document or previous PR runs.
