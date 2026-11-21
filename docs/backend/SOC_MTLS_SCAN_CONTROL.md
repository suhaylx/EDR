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
