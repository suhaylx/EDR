# Agent enrollment PostgreSQL foundation (BE-001)

Status: **draft; not deployed or production-approved**. The SQL schema and read-only Go identity lookup support the existing `VerifyAgentCertificate` helper. This is not an enrollment protocol, certificate issuer, or production listener.

## Migration and rollback

Run `backend/migrations/0001_agent_enrollment.up.sql` once with a privileged, operator-controlled migration role against an isolated PostgreSQL instance. Record the applied version using the operator's migration system. The script is transactional but **not idempotent** and must not run on API startup. The migration has no automatic destructive rollback: back up and plan retention before any manual DROP.

Grant the identity-reading API role SELECT only on the identity tables. Use a separate enrollment/audit writer role for enrollment and revocation; do not grant the API role schema ownership, UPDATE, DELETE or TRUNCATE. Set PostgreSQL TLS verification, timeouts, bounded connections, encrypted backups, and credential rotation at deployment.

## Enrollment transactions (future work)

1. Authorize a tenant operator and validate a short-lived single-use enrollment challenge and device proof of private-key possession.
2. Validate tenant, agent, platform, and issued client-auth certificate SAN `spiffe://turansec.local/tenants/{tenant}/agents/{agent}`.
3. In one transaction, create the agent, register the **DER leaf SHA-256** fingerprint with validity window, and append an enrollment audit event. Never store private keys.
4. Rotate certificates by revoking the previous active row and appending audit before inserting and auditing the new certificate, in the same transaction.
5. Revoke an agent using `edr_agents.revoked_at` or a leaf using `edr_agent_certificates.revoked_at`; append audit in the same transaction. Disabled tenants must be denied.

The partial unique index enforces at most one unrevoked certificate per tenant/device. The registry checks tenant disablement, agent revocation and certificate revocation; `VerifyAgentCertificate` additionally checks TLS trust, SAN, EKU, fingerprint and certificate validity.

## Tests and outstanding security gates

The new unit tests use an in-process `database/sql` fake connector to check tenant/device parameters, missing enrollment, malformed fingerprints and database outages. **They are not live PostgreSQL tests.** Before merge, run an ephemeral PostgreSQL migration test for foreign keys, partial uniqueness, revocation, rotation, cross-tenant isolation, audit transactions and restart persistence.

The existing localhost-only Go lab server still uses `EDR_DEV_TOKEN` and in-memory data. This registry is **not wired to it**. No PostgreSQL driver, production TLS listener, enrollment endpoint, durable queue or signed command channel is configured here. Do not expose the lab server or shared token to a public network. Agent 1 InfoSec and Agent 3 independent QA approvals remain mandatory.
