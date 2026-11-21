# SOC operator mTLS scan scheduling — draft, isolated listener

This module is **not** mounted in the development bearer-token server.
`NewSOCMTLSServer` builds a separate TLS 1.3 server that requires verified
client certificates from a dedicated **operator CA**, not the device CA.
The application checks a single URI SAN:

`spiffe://turansec.local/tenants/{tenant}/operators/{operator}`

The database's `edr_soc_operators` roster must be populated using a separately
approved provisioning process with exact SHA-256 client leaf fingerprints and
a scoped `viewer` or `scanner` role. Certificate issuance, role management
UI, and operator onboarding are **not included**. Key storage, signed policy,
and InfoSec approval remain prerequisites.

## Commands (operator certificate required)

- `POST /soc/v1/tenants/{tenant}/scan-jobs`:
  `{"agent_id":"win01","request_id":"operator-request-001","scan_root":"C:\\Lab\\sample.txt"}`
  returns HTTP **201** with `{"job_id":"UUID","created":true}`.
  An identical retry returns HTTP **200** and the same UUID with `created:false`.
  A reused request key with changed device/target/owner returns HTTP **409**.
- `POST /soc/v1/tenants/{tenant}/scan-jobs/{uuid}/cancel` with an empty body
  returns **204** only for a pending job created by this scanner operator;
  leased and completed jobs cannot be cancelled by this operation.

The server enforces tenant matching between the verified operator certificate,
database roster and route. The SQL functions recheck operator revocation,
tenant disablement and endpoint revocation under locks. A `viewer` may not
schedule or cancel scans. The Rust endpoint independently enforces its own
laboratory scan root, and only path scans are supported.

This is an opt-in server constructor; it does not start a network listener,
configure PostgreSQL drivers, grant database permissions, install certificates,
or deploy. Operators must never use the development bearer token as a
replacement for their own mTLS identity. Independent security and QA review
required before exposing any listener.

## SOC read-only scan history (BE-131–135)

Authenticated `viewer` and `scanner` roles can now read tenant-scoped
data on the **operator mTLS** listener:

- `GET /soc/v1/tenants/{tenant}/scan-jobs?state=pending&limit=25&offset=0`
  returns job history with state, agent, target, attempt count and timestamps.
- `GET /soc/v1/tenants/{tenant}/scan-jobs/{uuid}`
  returns one job's current status.
- `GET /soc/v1/tenants/{tenant}/scan-results?agent_id=win01&verdict=malicious&limit=25&offset=0`
  returns completed scan evidence, optionally filtered by agent and verdict.
- `GET /soc/v1/tenants/{tenant}/scan-results/{uuid}`
  returns durable ClamAV verdict detail for one job.
- `GET /soc/v1/tenants/{tenant}/scan-stats`
  returns counts by job state plus the malicious-verdict count.

Listings are limited to 100 records per request and an offset of 10,000.
Responses never select lease tokens or lease owner capabilities, are marked
`Cache-Control: no-store`, and enforce tenant ownership in each database
query. These APIs are for operator mTLS clients only; they are not mounted
in the shared development-token dashboard. Offset pagination is suitable for
the initial lab; snapshot/keyset pagination for high-volume production
remains a performance improvement.

## Malicious ClamAV alert lifecycle (BE-136–140)

Migration `0011_soc_malware_alerts.up.sql` automatically inserts one durable
tenant-bound SOC alert when a scan result is committed as `malicious`.
`clean_by_signature`, `error` and `unscanned` do not generate a confirmed
malware-signature alert. No endpoint action is triggered.

On the operator mTLS listener:

- `GET /soc/v1/tenants/{tenant}/alerts?state=open&limit=25&offset=0`
  lists the tenant's alerts (viewer/scanner roles).
- `GET /soc/v1/tenants/{tenant}/alerts/{uuid}` gives a single alert.
- `POST /soc/v1/tenants/{tenant}/alerts/{uuid}/ack`
  acknowledges an open alert (scanner role).
- `POST /soc/v1/tenants/{tenant}/alerts/{uuid}/resolve`
  with `{"note":"Reviewed in SOC lab"}` resolves an acknowledged alert;
  a nonempty audit note is required (scanner role).
- `POST /soc/v1/tenants/{tenant}/alerts/{uuid}/reopen` reopens a resolved
  alert for further investigation (scanner role).
- `GET /soc/v1/tenants/{tenant}/alert-stats` summarizes open,
  acknowledged and resolved alerts.

Every state change records the operator ID in PostgreSQL and requires a
verified, active operator role. Transitions are conditional on the current
state, reject stale repetitions, and never allow cross-tenant mutation.
This is analyst workflow state only, not an automated investigation or
remediation engine. Production identity provisioning, SOC frontend integration,
alert delivery, case management and retention policy still require approval.

## Endpoint inventory and investigation (accelerated sprint Day 2)

An authenticated SOC operator with `viewer` or `scanner` role may read:

- `GET /soc/v1/tenants/{tenant}/endpoints?platform=windows&health=online&limit=25&offset=0` — bounded, filtered device inventory
- `GET /soc/v1/tenants/{tenant}/endpoints/{agent_id}` — one device's last reported platform, version, ClamAV readiness and heartbeat count
- `GET /soc/v1/tenants/{tenant}/endpoint-stats` — fleet totals by platform and health state
- `GET /soc/v1/tenants/{tenant}/endpoints/{agent_id}/timeline?limit=25` — recent scan jobs and malware alerts for that device, ordered newest first

All queries are tenant-scoped in PostgreSQL and are reached only through
the **operator mTLS** listener. No lease tokens, certificates or secret
material are returned. Listings permit at most 100 items, and timeline
queries permit at most 100 events.

Health is computed using **database time**, not a device-supplied clock:

| Health | Meaning |
| --- | --- |
| `online` | Recent heartbeat (within 5 min) and local ClamAV PING ready |
| `degraded` | Recent heartbeat, scanner PING not ready |
| `stale` | Heartbeat older than 5 min |
| `unseen` | No heartbeat ever recorded |
| `revoked` | Administratively revoked endpoint |

Liveness and readiness are reported telemetry, **not tamper-resistant
attestation**, and do not prove the device is malware-free. Disabled tenants
are excluded entirely. The timeline is a lightweight investigation feed,
not full process-tree correlation, live threat hunting or event telemetry.

## Analyst case assignment and immutable activity (accelerated sprint Day 3)

Migration `0012_soc_alert_activity.up.sql` adds per-alert assignment
metadata and an append-only PostgreSQL activity feed. Existing alerts are
backfilled with an initial `system/created` event only; the migration does
**not** invent historical actors or earlier transitions. A database superuser
can still alter records, so this is not tamper-proof cryptographic evidence.

All endpoints require the **separate verified SOC operator mTLS listener**:

- `GET /soc/v1/tenants/{tenant}/my-alerts?limit=25&offset=0` —
  unresolved alerts assigned to the *authenticated* operator, not to a
  client-supplied operator ID (viewer or scanner role).
- `POST /soc/v1/tenants/{tenant}/alerts/{uuid}/assign` with
  `{"operator_id":"analyst2"}` — assign an open/acknowledged alert to
  an active scanner in the same tenant (scanner role).
  `{"operator_id":""}` unassigns it.
- `POST /soc/v1/tenants/{tenant}/alerts/{uuid}/notes` with
  `{"note":"Investigated signer and scan context"}` — append a bounded
  analyst note; returns HTTP 201 and an activity ID (scanner role).
- `GET /soc/v1/tenants/{tenant}/alerts/{uuid}/activity?limit=25&offset=0` —
  newest-first activity entries, including creation, assignment,
  notes, acknowledgment, resolution and reopening (viewer/scanner role).

The normal alert list/detail now also includes `assigned_to` when set.
The database rechecks tenant, operator role and revocation for mutations.
Assignments reject inactive/non-scanner assignees and resolved alerts;
conflicting/replayed operations return HTTP 409. Notes reject empty,
control-character and oversized content. Update/delete of activity records
are denied by a database trigger (subject to DB superuser and privilege
limitations).

This work does **not** perform process termination, network isolation,
quarantine, deletion or any other endpoint action. No operator
provisioning UI, signed release, on-host installation, or live lab evidence
is implied. Before any production use, Agent 1 must approve the DB role
grants and operator CA, and Agent 3 must rerun PostgreSQL/Go/Rust CI and
independent cross-tenant/revocation tests on the exact integration head.
