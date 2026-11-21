# Agent 5 — Multisignal alert triage and retained source inspection (lab)

Status: **draft frontend integration**, not an incident-response or production deployment.
Review PR #76, based on upstream PR #55 / integrated candidate PR #49.
This does not supersede standalone frontend PR #26, scan evidence PR #53/#54,
or InfoSec/QA/Backend security approvals.

## Actual React screens

1. **Security alerts** — `MultisignalAlertTriage.tsx` uses already decoded
   `GET /api/detections` records. It filters by severity (including
   unclassified), numeric Sysmon event type known/unknown, and returned
   endpoint/rule/source/target metadata. Status count is live and
   labels/input/select are native controls. The UTC 1/7/30-day time
   selection is performed against the server's overview `generated_at`
   before any local search or severity aggregation.
2. **Inspect retained source event** — `RetainedSourceInspection.tsx`
   renders the selected event only when the **Go event `id` AND
   `device_id` both match** the already fetched `GET /api/events`
   response. The endpoint is never queried by a guessed identifier.
   The Go event ID and the Windows `source_record_id` (EventRecordID)
   are explicitly distinguished. If no match exists among the maximum
   100 most recent returned API events, show an unavailable/evicted
   state, **not** proof that the event never happened.
3. **Investigation navigation** — existing read-only process evidence
   request remains accessible only if the returned detection or source
   actually includes a process GUID. For detections without a process
   GUID, source inspection is the supported local drill-down.

Both components are plain original React/TypeScript. They contain no
containment, isolation, quarantine, policy mutation or live endpoint
action. Text is rendered as React text nodes; no HTML injection.
Clipboard Sysmon Event ID 24 source detail/fields are suppressed
from the source inspection window even for a malformed sender report.

## Existing Go lab API contract (Agent 2 review required)

- `GET /api/detections`: `id`, `device_id`, `rule_id`,
  `category`, `severity`, `confidence`, `process_guid`,
  `process_image`, `evidence_event_id`, `load_event_id`,
  `evidence_source_event_id`, `target_object`, `module_path`,
  `file_create_event_id`, `observed_at`, `explanation`.
- Prefer `evidence_event_id` for the Go event reference; fall back to
  legacy `load_event_id` only when the newer field is absent.
  **Do not** treat the generic evidence as DLL execution, a
  FileCreate event as module load, or `evidence_source_event_id=0`
  as a known Sysmon class.
- `GET /api/events`: at most 100 decoded records with `id`,
  `device_id`, `source_event_id`, `source_record_id`,
  `time`, `received_at`, `time_origin`, and bounded,
  allowlisted metadata. Go event `id` is the correlation key;
  Sysmon `source_record_id` is only display metadata. No
  server-side pagination or durable historical guarantee exists.
- All data is in-memory, shared development bearer-token lab
  data. There is no verified endpoint signature, production RBAC,
  tenant boundary or reliable historical retention. A matching ID
  is **not** an attestation of event authenticity.

## Verification and release gates

- `frontend/tests/multisignal-alert-triage.test.mjs`: severity
  normalization, unknown classes, UTC window filtering, source
  identity precedence, cross-endpoint and EventRecordID collisions.
- `frontend/tests/agent5-two-milestones-render.test.mjs`: semantic
  labels/live counts, source match/unavailable states, React escaping,
  non-privileged controls, clipboard metadata handling.
- GitHub Actions `frontend-ui-checks`: strict TypeScript, Node
  typed suite, Vite build; plus `starter-ci` and relevant upstream
  Windows-agent checks. Check latest feature commit results.
- Agent 2: review type/source relationship, identity, endpoint
  lookup semantics, server-side tenant filtering and durable
  pagination proposal before integrating further.
- Agent 3: independently run keyboard Tab/Enter/Space, NVDA/Orca,
  200% zoom, light/dark/forced-colors, malformed source input,
  same-ID different-device, clipboard privacy and browser E2E.
- Agent 1: approve behavioral detection provenance and distinguish
  event observation from attack-chain causality.
- PM: stack/reconcile PR #76 with PR #55/#49, PR #26, and scan
  fixes PR #53/#54; do not silently overwrite branches or
  merge without review. No live Windows/Linux or native companion
  IPC validation is claimed here.
