# P0 mTLS agent identity probe — lab integration contract

**Status:** code-review-only increment. This is **not** production mTLS enrollment, agent authentication for telemetry, or a live deployed server.

The Go handler `GET /api/agent/v1/identity` is mounted separately from the legacy shared-bearer development API. It returns a JSON object with `tenant_id` and `agent_id` **only after** `VerifyAgentCertificate` validates the direct TLS peer and `AgentIdentityRegistry` confirms a currently enrolled, non-revoked tenant/device and leaf fingerprint.

- Missing/unverified peer certificate, wrong tenant/device, revoked leaf, expired/future certificate, or fingerprint mismatch: **401**.
- Registry unavailable or unconfigured: **503**, fail-closed.
- Non-GET method: **405**; no caching of responses.
- The `EDR_DEV_TOKEN` header is ignored by this endpoint; a browser bearer token cannot impersonate a device.

## Critical limitations and next integration step

`backend/cmd/server/main.go` still constructs `edr.Server` **without** an identity registry and still starts an HTTP development listener, so the probe deliberately returns **503** there. **Do not enable it by pointing a public unauthenticated reverse proxy or trusting forwarded certificate headers.** Agent 2 must separately mount an actual `PostgresAgentIdentityRegistry`, require TLS 1.3 with `tls.RequireAndVerifyClientCert` and a private controlled CA on a dedicated agent listener, and authorize heartbeat/ingest/scan lease using the returned principal (never a tenant or agent ID in request JSON). A successful probe alone does not secure the pre-existing `/api/agents`, `/api/events` or scan APIs.

## Verification / release gates

- `cd backend && go test -race -count=1 ./... && go vet ./...`
- `go test ./internal/edr -run 'TestAgentIdentityProbe|TestRealMutualTLS' -v`
- Agent 3 negative HTTP and real TLS handshake tests for no client cert, untrusted CA, wrong SAN, revoked and rotated fingerprints, expired certificate, disabled tenant and PostgreSQL disconnect; include failure-closed restart tests.
- Agent 1 reviews CA authority, replay protection, certificate lifecycle and signed commands; Agent 5 must show **unverified / not instrumented**, never a healthy enrolled endpoint based only on this probe.
- Operator-run Windows Server 2022/Ubuntu 24.04 EICAR-only lab and Sysmon checks are **NOT RUN**; no PR may be merged or deployed on this evidence alone.
