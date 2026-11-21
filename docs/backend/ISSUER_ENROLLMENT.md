# TuranSec EDR — authenticated issuer enrollment boundary (P0)

**Status:** draft backend milestone. The implementation is an issuer-only **finalization** endpoint and TLS server constructor. It does not generate enrollment challenges, issue X.509 certificates, manage issuer keys, expose a public signup endpoint, or deploy an agent. It is not enabled by the current localhost-only developer server.

## Trust boundary

`NewIssuerEnrollmentMTLSServer` constructs a **separate** TLS 1.3 listener with `RequireAndVerifyClientCert`, an issuer-only client CA pool, an explicit host:port, and a pinned set of approved issuer client certificate fingerprints, tenant IDs and actor IDs. It does not listen until operators explicitly start it after InfoSec approval. The issuer TLS trust pool must not be the normal agent CA or the system root store.

Request: `POST /issuer/v1/tenants/{tenant}/agents/{agent}/enroll/complete` with `Content-Type: application/json` and a client certificate approved for exactly that tenant. The service ignores actor/tenant headers; the trusted actor comes from the pinned issuer grant, and tenant/device identity comes from the canonical URL and the signed CSR / issued certificate.

JSON schema (byte slices are standard base64-encoded JSON strings; no real secrets in examples):

```json
{
  "challenge_id": "11111111-1111-4111-8111-111111111111",
  "challenge_secret": "<base64 of 32-byte cryptographically random secret>",
  "platform": "windows",
  "csr_der": "<base64 of signed PKCS#10 CSR DER>",
  "certificate_der": "<base64 of pre-issued agent leaf certificate DER>"
}
```

No `actor_id`, tenant claim, private key, or certificate-issuance authority is accepted from the body. All responses disable caching, bodies are capped at 192 KiB, JSON unknown fields and trailing documents are rejected, and no raw secrets or SQL errors are returned. Success is HTTP 204, invalid input 400, unapproved tenant 403, enrollment replay/ineligible 409, store failure 503. Missing or invalid issuer client certs must fail at TLS authentication or the handler's pinned-leaf check.

## Challenge-bound proof of private-key possession

1. A separately authenticated challenge issuer generates **32 random bytes** using a CSPRNG and writes the SHA-256 digest, a UUID challenge ID, tenant/device pair and short expiry to `edr_enrollment_challenges`. The original secret is delivered only through an approved, authenticated provisioning channel. Challenge issuance and delivery are **not** implemented here.
2. The agent generates its **own** private key (never leaves the endpoint) and a signed PKCS#10 CSR with the precise URI SAN `spiffe://turansec.local/tenants/{tenant}/agents/{agent}`, no extra SANs, and Subject `serialNumber` equal to `EnrollmentCSRChallengeSerial(challengeID, identity, secret)`. This is `ts-enroll-v1-` followed by hex SHA-256 of the domain-separated challenge ID, tenant ID, agent ID and original secret. The CSR signature binds the challenge to the key and prevents reuse of an old CSR for a different challenge.
3. An authorized issuer validates the CSR and its signature, checks the agent identity and challenge binding, signs a client-auth leaf with **the same** public key using an approved agent CA, and validates the issued certificate's URI SAN, key usage, validity, SPKI match and full chain against a controlled **agent** CA root. The certificate-signing operation is **not** implemented in this milestone.
4. Over issuer-only TLS, the authorized issuer submits the full request above. `NewIssuerEnrollmentHandler` rechecks signed challenge binding, trusted issued certificate chain, key match, tenant/device, certificate validity and the pinned issuer identity.
5. Only then, the `PostgresEnrollmentStore` invokes `edr_complete_agent_enrollment` to atomically consume the expiring single-use challenge, register the device and leaf fingerprint, and append immutable-intent audit records. Replayed, wrong-tenant, expired, disabled or duplicate enrollments fail closed.

**Important:** This endpoint is a trusted issuer service boundary, **not an agent-facing self-enrollment endpoint**. Agents must not receive issuer-client credentials; a secure agent-to-issuer provisioning workflow and token delivery remain architecture/security-review work.

## Permissions, operations and remaining gates

The issuer service needs narrowly scoped SQL permissions for the atomic enrollment function and its dependent table operations. Use a separately provisioned credential and PostgreSQL TLS verification. Do not grant the issuer role schema ownership or superuser. The audit table's append-only protection is a database trigger and role separation, not cryptographic tamperproofing against a database owner. Rotate/revoke pinned issuer client leaves and redeploy the allowlist promptly; CA trust alone is not sufficient authorization.

To verify from the backend root: `go test -race -count=1 ./...` and `go vet ./...`; GitHub `starter-ci` covers both Go and Rust. Draft PR #31 separately has disposable PostgreSQL tests for atomic enrollment, challenge replay, rotation and migration ordering.

**Blocking before merge/production:** independent Agent 1 InfoSec review of challenge delivery/issuer authentication and TLS configuration; Agent 3 QA of negative paths, exact certificate boundaries and database outages; real Windows/Linux lab enrollment and telemetry/scan smoke evidence. No changes to the lab bearer-token server, no production credentials or listener, no public development ports, no merge or deployment.
