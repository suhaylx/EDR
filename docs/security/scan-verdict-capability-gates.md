# Security scan verdict capability gate (Agent 1, v1, 2026-11-21)

**Status:** laboratory control-plane safety patch; not production AV verification. Scope: `backend/internal/edr/scans.go` and `scan_capability_test.go`, on the review branch. Parent lab MVP: PR #5; Rust scan worker: draft PR #16, issue #17.

## Finding and behavior
The current Rust worker has no quick/full profiles and returns `unscanned`. The existing Go backend accepted `clean_by_signature`, `malicious` or `suspicious` completion for any scan type. This is a protection-truthfulness issue, even if clients are currently laboratory clients.

For `quick` and `full`, reject success/positive detection claims on receipt. Allow only `unscanned` or `error`, mapping either to `failed`. The rule is enforced by the server, not the dashboard. `path` scan results retain current contract, but remain untrusted lab reports until device authentication and real ClamAV validation are implemented. The test uses synthetic API state, NOT real signatures or threats. Do not display unscanned as completed.

## Production-bound ScanRequestV1 / ScanResultV1 (proposed)
`ScanRequestV1`: `schema_version`, `tenant_id`, `device_id`, `command_id`, `profile` (quick/full/path/scheduled), `policy_id`, `policy_revision`, `allowed_root_ids`, `issued_at`, `expires_at`, `nonce`, `max_bytes`, `max_duration_ms`, `max_archive_expansion_bytes`, `signing_key_id`, `signature`. Authenticate enrolled device over mTLS, authorize scope server side, and require agent-side signature, monotonic expiry and anti-replay validation. Commands cannot provide arbitrary executable arguments.

`ScanResultV1`: original request/lease IDs, tenant/device, capability version, monotonic start/end plus UTC receipt time, scanned and skipped files/bytes, timeout count, engine name/version, *verified locally* signature DB version/update timestamp/integrity state, result `malicious | suspicious | clean_by_signature | error | unscanned`, optional signature name only for real named detections, bounded detail and error codes. `clean_by_signature` is **not** guaranteed safe. A stubbed EICAR response is a protocol test, not a real AV detection. A stale/unavailable DB or daemon failure is degraded/error, never healthy.

## Agent 2 implementation handoff
1. Add versioned signed commands and tenant/device mTLS identity; reject absent/revoked certificates, mismatched tenant, expired commands, replay, and wrong device. Never promote the dev bearer token to production.
2. Implement real ClamAV 1.5.5 quick/full/path/scheduled profiles: signed official DB updates; controlled freshness and integrity checks; bounded file/archive bytes, time, concurrent workers and CPU/I/O; explicit per-target skips and cancellations. Make worker capability claims **server-verified policy/agent attestations**, not arbitrary client booleans.
3. Path scanning must use handle-relative, no-follow open within a policy-approved root, with OS-specific reparse-point and race tests. A canonicalize-then-open check alone is TOCTOU vulnerable. Keep clamd loopback/Unix socket only.
4. Persist tenant-scoped job state and append-only evidence. Verify signed commands and protection policy across restart/offline retry. Separate server receipt time from sender-declared observation time.

## Agent 5 UX handoff
Show scan phase `queued | leased | completed | failed | expired` separately from verdict. For quick/full in the current lab, show `NOT IMPLEMENTED — UNSCANNED` or `SCAN ERROR`, not `Protected` or `Clean`. Show engine and official DB freshness only if instrumented; otherwise `NOT INSTRUMENTED`. For incident triage, keep raw Sysmon Event 11 (file create) separate from EID7 (actual image load), alert confidence separate from severity, and synthetic events visibly labeled.

## SOC-001, SYS-003, IR-001 requirements
Posture signals need server-received heartbeat age/offline days, per-rule actual firings (not policy installation counts), FP feedback, failed/expired scans, authenticated ClamAV DB age, Sysmon EID1/3/7/8/10/11/12-14/19-22/25/29 coverage and loss, policy hash drift and tamper audit. Uninstrumented metrics are `null` plus an explicit `NOT INSTRUMENTED` state, never zero or green.

Correlate only inside `tenant_id + device_id + boot/session` with source event IDs and ingestion IDs retained separately. An EID11 creation is never a DLL load; only EID7 can assert observed loading. EID22 DNS lookup does not demonstrate EID3 network connection; process parent without corroborating EID1 is reported-only lineage; EID10 access is not proof of code injection. Handle missing coverage and time skew without asserting absence of compromise. Prefer low-confidence alert-only heuristics until signer, source authenticity and false-positive controls are tested.

## Agent 3 acceptance
- Go unit regression for every unsupported mode x successful verdict, plus allowed error/unscanned; verify rejection does not mutate job state.
- `cd backend && go test -race -count=1 ./...` and `go vet ./...` on exact PR head, plus CI.
- Real isolated ClamAV 1.5.5 EICAR, benign and daemon-down/DB-corrupt/timeout tests, with actual captured DB version and signature. Never claim real AV success from a stub.
- Cross-tenant/cross-device, replay, wrong-boot correlations; Windows Sysmon event coverage/loss, Linux platform flags; signed maintenance authorization and quarantine/restore rollback.
- UI must prove missing/failed is never rendered as healthy; end-to-end authenticated evidence chain required for production.

**Release gate:** Block production deployment. This patch prevents one misleading state, but does not authenticate lab clients or establish that any AV scan actually happened.
