# Backend scan job API — initial implementation

**Status:** Tested Go control-plane prototype, **no actual endpoint scanner**. Run only on localhost with a temporary `EDR_DEV_TOKEN`; in-memory jobs disappear at restart. The token identifies neither tenants nor endpoints. Requires per-device mTLS, RBAC, durable queue, signed commands, audit and an actual Rust/ClamAV scanner before real deployment.

## Operator creates a job

```http
POST /api/scan-jobs
Authorization: Bearer <development token>
Content-Type: application/json

{"agent_id":"win-lab-01","request_id":"first-test-001","scan_type":"quick"}
```

Types: `quick`, `full`, `path`. For `path` require a validated absolute local path (Windows `C:\\Windows\\System32`, Linux `/home/user`). UNC/network paths, relative paths, dot segments and control characters are rejected. These are input-shape validations, not a sandbox or path authorization.

Job response: `id`, `agent_id`, `request_id`, `status: queued`, timestamps. Repeated identical request ID for a device returns the existing job; different parameters with the same key are rejected.

## Agent leases one job

```http
POST /api/agents/win-lab-01/scan-lease
Authorization: Bearer <development token>
Content-Type: application/json

{}
```

Response: the scan job with a rotating `lease_id`, status `leased`, and `lease_until`; returns HTTP 204 if queue empty. The lease expires in 60 seconds and can be reissued with a new lease ID; an old lease cannot complete a retried job. A job expires after 30 minutes unless completed. Actual scanning and retries require a future Rust client.

## Agent reports a scan result

```http
POST /api/scan-jobs/<job-id>/result
Authorization: Bearer <development token>
Content-Type: application/json

{"agent_id":"win-lab-01","lease_id":"<lease from prior request>","engine":"clamav","verdict":"clean_by_signature","engine_version":"test","database_version":"test"}
```

Allowed verdicts: `malicious` (requires `threat_name`), `clean_by_signature`, `suspicious`, `error`, `unscanned`. `error` or `unscanned` yields a `failed` job, not false health. Successful result is `completed`. This endpoint currently *accepts claimed results only*; it does not contact clamd. Agent-scoped, mTLS-authenticated verification is required before production use.

`GET /api/scan-jobs` lists scan history without exposing active lease capabilities. Go tests cover request validation, idempotency, concurrent leases, cross-agent mismatch, stale results, expiry and HTTP authentication.
