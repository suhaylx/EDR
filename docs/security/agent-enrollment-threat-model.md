# TuranSec EDR - Agent Enrollment Threat Model (P0 draft)

Current status: functional security requirements, not a completed implementation.

## Trust boundaries

- Endpoint Rust core has a device identity distinct from a user dashboard session.
- Go management plane authorizes each command for one tenant and scoped device.
- Local UI is unprivileged and accesses service state through restricted IPC.
- ClamAV and Sysmon worker/service failure must not interrupt core supervision.
- AD/LDAPS discovery bind credentials remain on the protected backend side.

## Attacker actions and mandatory countermeasures

| Threat | Expected mitigation | Acceptance test |
| --- | --- | --- |
| Cross-tenant command | Server-side tenant/device binding | Wrong-tenant command rejected |
| Replayed maintenance token | Nonce, expiry, single-use audit state | Replay rejected |
| Expired/revoked device cert | PKI lifecycle and deny-list/revocation | Connection rejected |
| Local UI tampering | Restrict IPC and config ACLs | UI cannot disable core |
| Malformed Sysmon policy | Worker isolation, validation, rollback | Core heartbeat/scan survives |
| Offline endpoint | Persisted expiring policy state and event queue | Restart/reconnect tested |
| Privileged local adversary | Defense in depth, tamper alerts; realistic limits | No claim of root-proof protection |

Implementation remains assigned to Agent 2 with Agent 1 security signoff and
Agent 3 independent QA before customer enrollment.

## Threat model revision 2 — concrete Agent 2 contract and QA gates

**Trust boundary:** a valid TLS connection alone is not a tenant-scoped
authorization. The Go service must verify the device's current registered
identity, certificate chain, revocation state and owner tenant for every
request, queue item, scan result, policy acknowledgement and telemetry batch.
Never accept tenant_id or agent_id merely because they appear in JSON.

**P0 enrollment sequence:** a tenant administrator with MFA and scoped RBAC
approves a device enrollment intent with short-lived single-use token, tenant,
platform/profile and expiry. Rust generates its own private key, preferably
nonexportable in a supported OS key store, proves possession with a CSR and
obtains a short-lived client-auth certificate bound to stable tenant/device
IDs (e.g. URI SAN namespace). Go persists enrollment grant consumption,
device certificate serial/public-key digest, tenant mapping, rotation
history and revocation. Re-enrollment requires an explicit separate grant.
Device hostname, IP and claimed OS are metadata, NOT identity proofs.

**Transport:** enforce certificate-chain validation, mTLS on every
agent-facing route, allowed EKUs, certificate expiry and server name,
pin/rotate trusted control-plane signing key. Reject unknown/revoked
certificates and immediately deny a deleted or moved device. Rotate
short-lived device certs through proof of possession and overlap windows,
audit issuance/rotation/revocation. Administrative JWTs and device certs
belong to separate principals and middleware.

**Signed command v1 (deterministic, immutable payload bytes):**
schema_version=1; command_id UUID; tenant_id; device_id; kind
(scan|policy_apply|quarantine|restore|maintenance); issued_at_utc;
not_before_utc; expires_at_utc; nonce; policy_revision and SHA-256;
requested_by; approved_by/approval_ref; reason; bounded typed arguments.
Sign a canonical byte representation with a rotated server signing key
(Ed25519 is one suitable scheme). Rust validates signature before
parsing/acting on untrusted args, exact device/tenant and allowed kind,
clock bounds, expiry, approved scope, monotonic revision and persisted
nonce/command-id replay record. Reject ambiguous fields, unknown schema
or unsupported policy revisions. Encrypt and fsync a bounded replay
journal and durable device policy state. Duplicate delivery returns the
original result, never executes again. Unknown wall clock or unsafe
offline expiry fails closed for state-changing commands.

**Command acknowledgement:** include command_id, device certificate
identity, applied policy digest, execution state, error code, bounded
detail, server receipt, agent boot ID and result/evidence digests.
Server records an append-only command transition and separate approvals;
signed commands cannot be silently edited after approval. Ensure
idempotent retry across process restart and duplicate queue delivery.

**Sensitive command requirements:** maintenance, uninstall, isolation
and restore require additional scoped, expiring, auditable approval.
Quarantine is reversible, with storage ACL and encrypted evidence.
No shared lab bearer may be accepted in a production build. Local UI
uses restricted IPC with read-only defaults and cannot directly create
signed privileged commands.

**DoS/degradation:** rate limit grant attempts and signed-command
delivery; cap queue bytes, per-host scan and telemetry rate, XML
parser depth, event payload size and CPU quotas. A compromised ClamAV
socket or malformed Sysmon payload must not terminate Rust core.
When secure transport fails, retain bounded encrypted offline queue,
show stale coverage and do not execute newly expired commands.

**Lab credential / tunnel boundary:** any administrator credential
previously shared in chat is exposed and must be rotated before reuse.
Restrict public RDP to trusted VPN/IP, require NLA and MFA where feasible,
and enable Windows Firewall, account lockout and audit. Isolate the
Windows Server and Ubuntu lab from customer systems. Bind the Go dev
API, ClamAV socket and clamd TCP only to the local trusted host; an SSH
tunnel that forwards a shared bearer token crosses a new trust boundary
and MUST NOT become a production device enrollment pattern. Rotate lab
bearer tokens after tunnel work and never reuse them as device identity.

**Mandatory Agent 3 negative tests:** wrong tenant/device, certificate
revoked/expired/unrecognized, cert rotate-and-revoke, grant replay,
duplicate command across agent restart, altered signature/argument,
clock skew, expired offline command, stale policy rollback, tamperable
local GUI, shared token against production route, dropped events, and
Sysmon worker crash without core interruption. P0 fails block deployment.
