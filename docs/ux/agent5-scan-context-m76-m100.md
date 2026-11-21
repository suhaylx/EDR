# Agent 5 — milestones M76–M100: scan-adjacent retained evidence

**Scope:** read-only React/TypeScript SOC lab implementation in private
`suhaylx/EDR`, stacked on Agent 5 scan-evidence draft PR #114 (and
upstream #100/#76/#55/#49). These are 25 independently named,
code-backed acceptance checks, **not** 25 verified production
capabilities or deployed endpoint agents.

## Feature

From a returned Go scan job, analysts can inspect **other records
returned for exactly the same opaque `agent_id=device_id`**,
including other jobs, heuristic detections, and telemetry events.
The code is in `frontend/src/scan-context.ts`, the UI in
`ScanEvidenceContext.tsx`, with a scan-history pivot in
`ScanEvidenceWorkbench.tsx` and navigation in `main.tsx`.

The selected job is never classified as a confirmed actual scan,
and no scan command is sent. Server-recorded job creation is
only a **request** timestamp, not an execution/completion timestamp.
Telemetry uses Go receipt time when present; when absent,
sender-reported time is displayed **as such**. Detection observed
time is also reported evidence, not attested time provenance.
The optional ±1h/±24h/±7d filters are symmetric distances from
job request time and **cannot establish a causal or threat
association**. When the selected job has no timestamp, nearby
time filtering fails closed to empty with an explicit explanation.

The endpoint source correlation uses exact, case-sensitive
opaque identity (not substring or case-folded hostnames).
A Windows source RecordID is never used as a global join key.
Returned telemetry is a max-100-record sample. Missing
sample matches are **not event loss** or proof the endpoint is safe.
The workbench provides local type/search/time/order filters,
stable time sorting, 25/50/100 row paging, live counts,
read-only exact Go event inspection, investigation seeds for
detected alerts, navigation to other retained jobs, and
no incident-close/quarantine/scan controls. Clipboard Sysmon
Event ID 24 is always shown as metadata only; it is not
included in the context text search.

## 25 named milestone acceptance checks

| ID | Requirement enforced in source and Node test |
| --- | --- |
| M76 | Identity joins require an exact opaque endpoint ID |
| M77 | Case-variant endpoint IDs do not silently coalesce |
| M78 | Matching GUIDs on different hosts do not join |
| M79 | Selected scan is excluded from "other jobs" |
| M80 | Counts are local to retained response samples |
| M81 | Scan/detection/event entries have distinct stable identities |
| M82 | Only numeric Windows Sysmon IDs receive Sysmon classes |
| M83 | Event 11 FileCreate is not Event 7 DLL/image load |
| M84 | Clipboard Event 24 displays no reported content |
| M85 | Clipboard body is not searchable in context |
| M86 | Go receipt timestamp takes precedence over sender time |
| M87 | Sender timestamp fallback is explicitly marked |
| M88 | Missing event times remain unknown |
| M89 | Temporal anchor is selected job creation, not scan execution |
| M90 | Missing anchor cannot produce nearby time matches |
| M91 | Inclusive ±1h boundaries are symmetric |
| M92 | Outside-1h events are excluded from 1h filter |
| M93 | ±24h window correctly bounds returned records |
| M94 | ±7d window does not imply durable retention |
| M95 | Future relative to overview generation is warned, not attested |
| M96 | Undated records remain in All, excluded from nearby windows |
| M97 | Scan/detection/telemetry filters do not merge source classes |
| M98 | Case-insensitive local search stays host-scoped |
| M99 | UTC offset-aware sorting and undated-last ordering |
| M100 | Stable bounded paging, empty cases, invalid parameters rejected |

Executable test: `frontend/tests/scan-context-25.test.mjs`.
Additional SSR tests:
`frontend/tests/scan-context-render.test.mjs` checks
semantic labels, focusable heading, time-source labels,
25-row rendering, safe XSS text escaping, Event 24
redaction, and zero-result/clock-skew messaging.

## Dependencies and release gates

- **Agent 1 InfoSec:** review the noncausality and Sysmon
  7/11/24 interpretations, and inability to infer installation,
  losses, tamper, signature freshness or protection.
- **Agent 2 Backend:** supply authenticated, tenant-scoped
  durable scan/telemetry APIs, verified received times,
  stable pagination and per-endpoint authorization.
  Current in-memory Go development token is not sufficient.
- **Agent 3 QA:** run real browser keyboard focus, screen
  reader (NVDA/Orca), 200% zoom, forced colors, light/dark,
  invalid-source/XSS, host collision, future/late clocks,
  token disconnect, multiple requests, and Windows/Linux
  lab E2E. SSR tests do **not** replace these.
- **PM:** coordinate stacked PR reviews and exact-head
  frontend/starter/Windows CI, and review before any merge.
  No native companion IPC or production rollout is claimed.

**Evidence rule:** The PR commit and CI status establish
test/build results only, not a production release.
