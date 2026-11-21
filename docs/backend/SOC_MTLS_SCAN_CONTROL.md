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
