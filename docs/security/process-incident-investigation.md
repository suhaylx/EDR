# Process lineage and incident evidence graph — laboratory increment

**Status:** Working Go graph query + original browser view built on the lab SOC branch. **Not a deployed endpoint sensor, a full infection verdict, or a complete historical incident database.**

## User-facing investigation flow

From **Security alerts**, select **Investigate [rule / endpoint]**, or open **Process & incident graph** and supply the endpoint plus actual `process_guid` / detection ID. The UI retrieves and displays the process lineage with a timeline of retained events, file/module evidence and detection records; also shows missing coverage, reported-only parent relationships and truncation.

The graph explicitly separates observed process-creation edges from parent-process values reported in other events. A file creation is not evidence of module execution; a `module_load` is shown only when that event exists. DNS query is not network connection. A detection is an investigative hypothesis, not an infected-machine verdict.

## Lab API contract

`GET /api/investigations?device_id=<id>&detection_id=<id>[&depth=4&max_nodes=250]`

OR

`GET /api/investigations?device_id=<id>&process_guid=<guid>[&depth=4&max_nodes=250]`

- Requires the existing development bearer token (NOT production authentication).
- The two seed selectors are mutually exclusive. `depth` 1..6; `max_nodes` 1..500; invalid selectors return HTTP 400 and unknown process/detection returns 404.
- `InvestigationGraph` returns `nodes`, `edges`, `gaps`, `truncated`, seed and data-source description.
- Nodes: `process`, `event`, `file`, `detection`; no fabricated `infected` state.
- Edges: `parent_process`, `observed_event`, `created_file`, `loaded_module`, `deleted_file`, `flagged_by_rule`, `linked_detection_evidence` with `provenance` and source evidence ID where available.
- Only events and detections with the exact requested `device_id` are processed. Source event ID linkage is bounded to the retained 2,000-event laboratory in-memory ring; missing history is never inferred.
- The current schema stores network/DNS details as an opaque event `detail`. The graph labels the event, but cannot prove network causality or identify a domain-to-IP link without future typed fields.
- The UI escapes all displayed backend strings. Read-only investigation queries perform no endpoint response or file execution.

## Testing and production blockers

`cd backend && go test -race -count=1 ./... && go vet ./...`

`node --check backend/web/app.js` from the repository root.

Implemented tests include: same-device parent-child process ancestry and descendants, DNS/network/file/module event coverage, detection-to-load linkage, report-only parent caveats, rejection of another device's events, unauthorized API, malformed graph selectors, nonexistent seed, and bounded graph truncation.

**Production blockers:** no real Windows Sysmon or Linux process-event collector, no mTLS/tenant isolation, no durable immutable event lake/cursors, no cross-reboot process identity model, no guaranteed source completeness, no verified URL/IP/entity stitching, no analyst incident state/assignee/audit/RBAC, and no automated infection-chain causal inference. A production-grade incident graph must preserve source channel, provider, EventID, event record ID, sensor policy/version, rule version and evidence hashes, with anti-replay and explicit drop/loss signals.

**Follow-on acceptance:** Agent 1 defines behavioral event relationships and false-positive/causality standards; Agent 2 implements secure durable normalized sources and incident case/grouping APIs; Agent 3 verifies no cross-tenant linkage and loss/out-of-order behavior, performs Windows/Linux lab checks; Agent 5 extends original accessible interactive graph with zoom/search/filter and linked evidence detail; Agent 4 tracks commits, CI and release blocker matrix. Kaspersky EDR is a functional/UI workflow benchmark, not a license to copy source/UI assets.
