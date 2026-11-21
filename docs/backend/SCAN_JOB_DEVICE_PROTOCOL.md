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
