# TuranSec EDR — InfoSec source review, 22 November 2026

## Decision and scope

**Reviewed baseline:** `f00cab502cf04ee92fed1210fb7ba295d92e9c36`, the merge of
PR #180. **Baseline engineering verdict: changes required.** A source-supported
expiry defect remains in enrollment and certificate rotation. The corrective
change needs independent review and successful PostgreSQL evidence from its
own exact commit before this finding can be closed.

**Installed-system and release verdict: not approved by this review.** This is
a bounded defensive source assessment by the newly assigned InfoSec agent.
It is not the original role owner's signoff, a formal GitHub approval, a
penetration test, a native-host acceptance result, or deployment authorization.
The scope does not include exploit payloads, active endpoint probes, or race
demonstrations. No execution result is inferred from source inspection.

The review followed the actual `edrd` serving path, its Go certificate and
transaction guards, PostgreSQL enrollment/rotation and restricted-role
bootstrap, and the authenticated Rust scan path. The source baseline was
available as a local Git checkout. No `AGENTS.md` was present in the repository
tree. Previous candidate CI results are historical evidence; this document does
not reattest their logs or transfer their result to a later correction.

## SEC-20261122-01 — enrollment expiry uses a stale transaction clock

**Priority:** P1 security correctness; must be corrected before enrollment or
rotation acceptance. **Evidence level:** source-confirmed logic defect;
runtime reproduction and corrective test results are not supplied by this
InfoSec pass.

Three related predicates use the transaction-start clock:

| Boundary | Exact baseline source | Source-supported concern |
| --- | --- | --- |
| Challenge consumption | [`0004_enrollment_challenges.up.sql`](https://github.com/suhaylx/EDR/blob/f00cab502cf04ee92fed1210fb7ba295d92e9c36/backend/migrations/0004_enrollment_challenges.up.sql), lines 45–52 | The consuming update records and compares `transaction_timestamp()`. A transaction can remain open beyond the challenge's real expiry, while this value still describes its earlier start. |
| Initial enrollment | [`0006_atomic_agent_enrollment.up.sql`](https://github.com/suhaylx/EDR/blob/f00cab502cf04ee92fed1210fb7ba295d92e9c36/backend/migrations/0006_atomic_agent_enrollment.up.sql), lines 23–41 | Certificate validity is checked against the same transaction-start value before tenant/device locking and challenge consumption. There is no fresh validity check after those operations. |
| Certificate rotation | [`0003_certificate_rotation.up.sql`](https://github.com/suhaylx/EDR/blob/f00cab502cf04ee92fed1210fb7ba295d92e9c36/backend/migrations/0003_certificate_rotation.up.sql), lines 27–48 | Replacement validity is checked before authorization/old-certificate locks. A replacement that expires during a wait is not revalidated before the existing leaf is revoked. |

The analogous distinction between transaction-start time and fresh time after
locking is already recognized in the scan-lease correction,
[`0013_scan_lease_wallclock.up.sql`](https://github.com/suhaylx/EDR/blob/f00cab502cf04ee92fed1210fb7ba295d92e9c36/backend/migrations/0013_scan_lease_wallclock.up.sql).
That migration replaces scan-lease functions; it does not replace the three
enrollment/rotation functions above.

The security implication is a weaker expiry boundary at the issuer's storage
layer. The rotation variant can also retire a usable old certificate for an
already expired replacement, causing loss of usable device authentication.
This does **not** establish an unauthenticated remote enrollment route:
`CompleteInitialEnrollment` is explicitly an issuer-authorized storage adapter,
the SQL functions revoke `PUBLIC` execution, and the runtime bootstrap does not
grant enrollment or rotation to the application runtime role. Those constraints
limit exposure but do not make the time predicates correct.

The correction should be additive and retain historical migrations. It should
check challenge expiry and certificate validity against fresh wall-clock time
after every relevant authorization/challenge/certificate lock, using the
intended `[not_before, not_after)` validity interval. Denial must leave the
challenge, old certificate, enrollment rows, and success audit unchanged.
Replacement must preserve function ownership, ACLs, security mode and configured
search path. Successful and denied authorized operations, expiry after waiting,
and upgrade/idempotence behavior need evidence on the final correction commit.

The standalone challenge consumer also reads tenant disablement through its
update join without an explicit tenant lock. Atomic enrollment already holds
an outer tenant lock. The corrective review should keep a consistent lock order
and make the standalone consumer's tenant authorization serialization explicit;
this observation has not been exercised against a running database here.

## Security controls actually inspected

These are source observations, not a claim that every possible bypass was
excluded or that the controls were exercised on deployed hosts.

| Area | Source observation and boundary |
| --- | --- |
| Actual service wiring | [`backend/cmd/edrd/main.go`](https://github.com/suhaylx/EDR/blob/f00cab502cf04ee92fed1210fb7ba295d92e9c36/backend/cmd/edrd/main.go) replaces the listener constructors' default handlers with `AgentAuthenticatedScanHandler` and `SOCApplicationHandler`. The review follows those installed handlers. Constructor defaults alone are not evidence of a bypass in the shipped `edrd` path. |
| TLS and listener exposure | [`agent_mtls_server.go`](https://github.com/suhaylx/EDR/blob/f00cab502cf04ee92fed1210fb7ba295d92e9c36/backend/internal/edr/agent_mtls_server.go) requires an explicit numeric loopback address, TLS 1.3 and verified client certificates, disables session tickets, and bounds headers and connection timeouts. Remote deployment still requires its separate reviewed transport design. |
| Device identity | [`agent_identity.go`](https://github.com/suhaylx/EDR/blob/f00cab502cf04ee92fed1210fb7ba295d92e9c36/backend/internal/edr/agent_identity.go) requires a verified matching leaf, client-authentication usage, current validity, an exact tenant/device URI SAN and a matching active registry fingerprint. Registry failures deny access. |
| Operator identity and scope | [`soc_operator_mtls.go`](https://github.com/suhaylx/EDR/blob/f00cab502cf04ee92fed1210fb7ba295d92e9c36/backend/internal/edr/soc_operator_mtls.go) uses the verified operator leaf, database role/fingerprint and tenant route. `edrd` loads separate agent/operator CA pools and rejects identical trusted public keys across them. Organizational CA ownership and provisioning remain operational controls. |
| Transaction authorization | [`certificate_transaction.go`](https://github.com/suhaylx/EDR/blob/f00cab502cf04ee92fed1210fb7ba295d92e9c36/backend/internal/edr/certificate_transaction.go) completes a bounded body read before database locking, reauthorizes the fingerprint in the mutation transaction, rechecks the actual TLS leaf after the authorization wait, and withholds success/lease-token responses until commit succeeds. A failed commit remains an ambiguous outcome for callers. |
| Database privileges | [`runtime_privileges.sql`](https://github.com/suhaylx/EDR/blob/f00cab502cf04ee92fed1210fb7ba295d92e9c36/backend/bootstrap/runtime_privileges.sql) separates registry/runtime logins and a constrained function owner, denies runtime enrollment/rotation/admin recovery, limits runtime function execution to an allowlist, removes schema creation and temporary-object privileges, and fixes function search paths. This is application-mediated tenant isolation; the shared database role is not a per-tenant credential. |
| Browser boundary | [`soc_application.go`](https://github.com/suhaylx/EDR/blob/f00cab502cf04ee92fed1210fb7ba295d92e9c36/backend/internal/edr/soc_application.go) rechecks operator identity for assets/session/API, rejects cross-origin browser contexts, uses no-store and restrictive CSP headers, strips asserted identity headers, and restricts static files to the expected build paths. Native mTLS clients can omit browser origin headers. |
| Endpoint transport and credentials | [`scan_mtls.rs`](https://github.com/suhaylx/EDR/blob/f00cab502cf04ee92fed1210fb7ba295d92e9c36/agent/src/scan_mtls.rs) uses explicit private CA trust, TLS 1.3, no proxy/redirect/plaintext fallback, bounded replies and timeouts. Unix credential reads apply no-follow and owner-only permission checks. Windows ACL enforcement is explicitly pending. |
| Scan-file boundary | [`scan_file.rs`](https://github.com/suhaylx/EDR/blob/f00cab502cf04ee92fed1210fb7ba295d92e9c36/agent/src/scan_file.rs) and [`worker.rs`](https://github.com/suhaylx/EDR/blob/f00cab502cf04ee92fed1210fb7ba295d92e9c36/agent/src/worker.rs) restrict the lab root and file size. Linux uses handle-relative `openat2` with beneath/no-symlink/no-mount-crossing resolution. This does not establish a production Windows reparse-safe open or a complete native service sandbox. |
| Verdict integrity | [`clamav.rs`](https://github.com/suhaylx/EDR/blob/f00cab502cf04ee92fed1210fb7ba295d92e9c36/agent/src/clamav.rs) bounds the stream and response format and distinguishes signature-clean, malicious, scanner-error and malformed replies. [`scan_runner.rs`](https://github.com/suhaylx/EDR/blob/f00cab502cf04ee92fed1210fb7ba295d92e9c36/agent/src/scan_runner.rs) refuses successful result reporting after lease-renewal failure and omits paths/tokens/signatures from its normal result log. A trusted, healthy local ClamAV deployment remains necessary. |

## Preexisting acceptance gates retained

The current acceptance document,
[`HOST_ACCEPTANCE.md`](https://github.com/suhaylx/EDR/blob/f00cab502cf04ee92fed1210fb7ba295d92e9c36/docs/HOST_ACCEPTANCE.md),
requires the following evidence. This review does not close these gates:

- Actual authorized Ubuntu 24.04 and Windows Server 2022 installation, service
  health/reboot behavior and full authenticated endpoint-to-SOC acceptance.
  Container/unit-test evidence and native compilation have narrower scope.
- Windows credential/configuration ACL enforcement, safe handle-based file
  opening, an accepted persistent service/installer and restricted local IPC.
  The current one-shot/bounded-batch executable does not establish those.
- Trusted publisher signatures and an independently provisioned verification
  key. Hash equality, CI package verification and a test signing key do not
  establish approved organizational publisher identity.
- Genuine ClamAV database/signature provenance and benign/EICAR/error behavior,
  with attribution through the full Rust/backend/SOC flow; genuine Sysmon
  records with Event 11 treated as creation and Event 7 required for load
  observation.
- Installed-service/database-compatible rollback, including failure paths and
  restored health, on the authorized native canaries.
- The designated security/QA owner's final acceptance and deployment owner's
  authorization for the exact artifacts, hosts and maintenance window.

The original security functionality specification also requires signed
tenant/device commands and policies, controlled maintenance authorization,
bounded worker behavior and realistic tamper protection. mTLS authenticates a
transport peer; the inspected code alone does not establish completion of all
those product requirements. The older specification contains historical
prototype-status language, so it is used as a requirements source rather than
a current inventory of implemented mTLS/database capabilities.

## Evidence and closure status

Only defensive source reading and report creation were performed by this
reviewer. No production endpoints, tenant credentials, enrollment service,
native installation, publisher key or live malware were used. No formal review
was submitted and no deployment was performed. PostgreSQL race/expiry
execution, dependency vulnerability scans, native-host acceptance and complete
accessibility acceptance are **not established by this report**.

The finding remains **open on the reviewed baseline**. Root owns the corrective
SQL change and its verification. An independent static review of that change
is appended below; it retains the
distinction between code review, observed test results, original-owner
acceptance and production readiness.

## Independent review of the corrective migration

**Source review result: no blocking defect identified in the inspected
correction. Hosted PostgreSQL verification remains pending.**

The reviewer inspected
[`0014_enrollment_wallclock.up.sql`](../../backend/migrations/0014_enrollment_wallclock.up.sql)
as supplied by root. The file's SHA-256 at review was
`a38b485f2803c9765e876ed0cf9dc311a52ada64a2dc5ab63ef7c1c9b287968f`.
This identifies the reviewed file contents; it is not a candidate commit or a
test result. Subsequent modifications require reconciliation with this review.

- Challenge consumption locks the enabled tenant, then the matching unconsumed
  challenge, before reading the wall clock. It denies an expired challenge
  without updating `consumed_at`. The tenant lock also serializes the standalone
  consumer with tenant disablement.
- Initial enrollment retains the tenant/device existence guard and locks the
  matching challenge before checking the certificate's current validity. A
  denied certificate returns before challenge consumption. The subsequent
  consumer operates on rows already locked by the same transaction; enrollment,
  certificate and success-audit inserts remain in that transaction.
- Rotation locks the enabled tenant, active agent and matching unrevoked old
  certificate before evaluating the replacement's `[not_before, not_after)`
  window. An invalid replacement raises an error before revocation or success
  audit. Subsequent insert/audit failure rolls back the operation rather than
  committing only the old certificate's revocation.
- The upgrade uses `CREATE OR REPLACE`, restores the previous security mode and
  function-local settings, and compares OID, owner, ACL, security mode and
  settings before accepting each replacement. No new enrollment/rotation role
  grant is introduced. Capability publication occurs within the same migration
  transaction and rejects an incompatible recorded capability version.

The review raised an integration requirement: migration-chain CI and
installation/package instructions must include `0014`; the corrected release
must require the `enrollment_wallclock` capability rather than silently accepting
a database with only the prior scan-lease capability. At the time of this
review, the inspected startup/bootstrap required only `scan_lease_wallclock`.
Root owns the associated integration changes.

Closure still requires successful hosted PostgreSQL results on the final commit,
including current-validity positives, expiry denials after waits, unchanged
state on denial, concurrent authorization behavior, and preserved metadata on
upgrade/reapplication. The reviewer has not executed those checks. This static
review does not change the native-host, publisher-signing, original-owner or
deployment gates above.
