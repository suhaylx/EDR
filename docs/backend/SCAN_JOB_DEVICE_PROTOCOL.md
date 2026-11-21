# BE-007 — Device-scoped scan-job lease protocol (review contract)

Status: **draft protocol, not a deployed Rust agent**. Implemented Go endpoints
live behind `AgentHTTPGuard` on a dedicated TLS 1.3 mTLS listener; this file
does not authorize exposing the handler directly.

## Identity and trust

The verified enrolled certificate identifies exactly one `tenant_id` and
`agent_id`. Request headers, JSON fields, query parameters and the Rust
process's local configuration cannot override this identity. A valid certificate
must be enrolled, active, not revoked, and bound to the requested route.
The backend also checks tenant/device status in PostgreSQL when claiming,
renewing or completing jobs.

## Endpoints (POST only)

Prefix: `/agent/v1/tenants/{tenant}/agents/{agent}/scan-jobs/`.

| Operation | JSON request | Success | Rejection |
| --- | --- | --- | --- |
| `claim` | empty | 200 JSON job + token; 204 no job | 401/403 identity; 503 DB |
| `renew` | `{"job_id":"UUID","lease_token":"UUID","lease_seconds":30}` | 204 | 400 malformed; 409 stale/expired/revoked; 503 DB |
| `complete` | `{"job_id":"UUID","lease_token":"UUID","success":true}` | 204 | 400 malformed; 409 stale/expired/revoked; 503 DB |

A claim response contains `job_id`, `scan_root`, `attempt_count`,
and a server-generated random `lease_token`. Tokens are capabilities:
never log, include in telemetry, or expose through SOC/UI. A retry of
`complete` may return 409 after successful completion; clients must not
interpret 409 as success. All requests require no-store handling and strict
body limits. Renewal duration is 5–300 seconds; lease owner is derived
from authenticated device identity.

## Rust integration gates (NOT IMPLEMENTED HERE)

1. Persist the enrolled device identity and private key in OS-protected storage.
   Never ship a shared development bearer token or skip server verification.
2. Verify the expected backend DNS name and pinned organization CA, and present
   the enrolled client certificate. Refuse plaintext, redirects and alternate hosts.
3. Serialize claim/renew/complete for one job. Renew before expiration only
   while scan execution is still active. Stop reporting success if renewal fails.
4. Resolve the scan path against an explicitly authorized root; reject traversal,
   symlink escapes, unapproved scan modes, and network paths.
5. ClamAV unavailable, timeout, or partial scan is **error/unscanned**, never
   clean. Submit success only when the agreed result persistence contract exists.
6. Test Windows and Linux with real ClamAV 1.5.5, real mTLS, disposable
   PostgreSQL, and revoked-device negative cases before canary.

## Release restrictions

This protocol is not a proof of running agent, secure key provisioning,
signed MSI, production CA issuance, or end-to-end malware detection.
Agent 1 InfoSec and Agent 3 QA sign-off are mandatory before release.

## BE-020 acceptance checklist

- [ ] Go CI and PostgreSQL 16 disposable migration chain pass on exact merged candidate SHA.
- [ ] Agent 1 reviews mTLS issuer trust, tenant/device binding, lease-token secrecy and revocation races.
- [ ] Agent 3 independently verifies stale token replay, renewal during disablement, retries and restart recovery.
- [ ] Rust agent uses enrolled private key and verifies backend DNS/CA; no development bearer fallback.
- [ ] Real ClamAV 1.5.5 detection and scanner-error tests run on isolated Windows and Linux lab endpoints.
- [ ] Scan result schema is durable and distinguishes malicious, clean-by-signature, error and unscanned.
- [ ] Signed packaging, rollback, audit trails and resource limits are approved before canary.
- [ ] No merge, production listener or endpoint rollout without explicit approvals.

## BE-111–115 durable verdict integrity (draft)

Migration `0008_scan_job_results.up.sql` requires:
- A composite foreign key `(job_id, tenant_id, agent_id)` to prevent
  a direct SQL result row from claiming a different tenant or device.
- Append-only scan results: application-level UPDATE/DELETE are rejected by a
  database trigger. A database superuser can still bypass database triggers;
  this is not a cryptographic audit log.
- Non-control-character signature/detail fields with strict field lengths.
- Atomic consumed lease + result insertion; same job cannot be completed twice.

The authenticated `POST .../scan-jobs/complete-result` request uses:
`{"job_id":"UUID","lease_token":"UUID","verdict":"malicious","threat_name":"Name","detail":""}`.
Valid verdicts: `clean_by_signature`, `malicious`, `error`, `unscanned`.
A `malicious` verdict requires a nonempty signature; all other outcomes
require an empty signature. A successful scan (`succeeded` job state) is
**not** a benign verdict—`malicious` also means the scan ran to completion.
The older boolean-only `complete` endpoint is retained for older lab
protocol consumers but does **not** constitute a durable malware result and
must not be used for endpoint detection evidence.

The disposable PostgreSQL chain workflow now tests malicious and clean
completion, scanner failures, missing scans, cross-tenant isolation, replay,
expired leases, revocation and immutability. No signed evidence or operator
alert generation is implemented in this change.
