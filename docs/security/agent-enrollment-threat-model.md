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
