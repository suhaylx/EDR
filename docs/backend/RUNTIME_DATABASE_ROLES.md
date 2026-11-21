# Runtime PostgreSQL roles

This candidate separates readonly certificate-registry access from operational
SQL. Apply schema migrations 0001–0013 first, then the operator-controlled
bootstrap in `backend/bootstrap/runtime_privileges.sql`. The service must not
run migrations or this bootstrap at startup.

## Provisioning

Use a dedicated EDR database. This bootstrap revokes public temporary-object
creation in that database and public-schema creation; it is not intended for a
database shared with unrelated applications.

An authorized operator first creates two distinct `LOGIN INHERIT` identities
with no superuser, role/database creation, replication or bypass-RLS capability.
Configure their authentication through the organization's approved PostgreSQL
authentication process. Keep passwords, certificate private keys and complete
connection strings outside the repository and terminal output.

The two identities must own no database objects and have no unrelated role
memberships. Supply their names to the bootstrap; these example names are
identifiers, not credentials:

```sh
psql service=edr_migration_admin -X -v ON_ERROR_STOP=1 \
  -v runtime_login=edr_service_login \
  -v registry_login=edr_registry_login \
  -v dedicated_edr_database=true \
  -f backend/bootstrap/runtime_privileges.sql
```

The `edr_migration_admin` service entry is operator-managed and must point at the
intended dedicated database. Do not use an application credential for this step.
The bootstrap creates no authenticated login and sets no password. Reapplying
it validates the existing roles and constant lock columns, then reapplies the
explicit grants. An unexpected privileged role or object owner causes failure.

Configure `edrd` with separate protected `registry_dsn_file` and
`runtime_dsn_file` paths. Both connections must reach the same database using the
two different logins. Registry lookup defaults to readonly transactions. The
runtime login receives only the operational grants below. Use verified
PostgreSQL TLS when the deployment topology requires network transport; a
disposable loopback SQL test does not validate deployment certificates.

## Privilege boundary

| Privilege role | Intended authority |
| --- | --- |
| `edr_identity_ro` | Read tenants, agents, registered agent-certificate fingerprints and SOC operator fingerprints/roles. No mutation-function execution. |
| `edr_runtime` | Read bounded-query source tables and execute eleven reviewed functions. No direct table writes or access to scan lease token/owner/expiry columns. |
| `edr_api_functions` | `NOLOGIN` owner of only the eleven authorization/operational functions. Narrow column writes and identity row-lock privileges; no table/schema/database ownership. |

Neither application login is a member of the function-owner role. None of these
roles may create public-schema objects or temporary objects, change trust fields,
disable triggers, alter tables, or administer PostgreSQL.

The eleven runtime functions cover:

- Reauthorize the exact agent certificate or operator certificate/role while
  holding shared authorization-row locks through the operational transaction.
- Claim, renew and complete a scan with an explicit scanner result.
- Record an endpoint heartbeat.
- Schedule and cancel an operator's pending scan.
- Change alert state, assign an alert and add an analyst note.

Enrollment, certificate rotation/revocation, enrollment-challenge consumption,
old boolean-only scan completion and expired-lease recovery remain outside the
runtime execution allowlist. Lease recovery requires a separately reviewed
maintenance identity; do not grant it implicitly to a listening service.

Each operational function uses `SECURITY DEFINER` with
`search_path = pg_catalog, public, pg_temp`. Application tables are explicitly
schema-qualified. `PUBLIC` function execution is revoked in the same transaction
as ownership/grant changes. Existing result-to-alert and alert-to-activity
triggers remain invoker functions and perform their inserts in the constrained
context of the outer operational function.

PostgreSQL row locks such as `FOR SHARE` require an `UPDATE` privilege on at least
one column of each locked table. A boolean `runtime_lock` column on tenants,
agents, agent certificates and operators is constrained to `false`. Only the function owner receives
`UPDATE(runtime_lock)`, solely to permit row locks. No operational function
changes that value. Trust columns such as disabled/revoked state, role and
certificate fingerprint remain unwritable.

## Transactional certificate authorization

The HTTP certificate check must be followed by one of these SQL guards inside
the same explicit transaction as the operational SQL:

- `edr_authorize_agent_certificate(varchar,varchar,bytea)` checks tenant,
  agent and the 32-byte SHA-256 fingerprint of the verified TLS leaf.
- `edr_authorize_operator_certificate(varchar,varchar,bytea,text)` checks
  tenant, operator, exact verified-leaf fingerprint and current viewer/scanner role.

The agent guard locks the active agent/tenant first, in the existing rotation
order, and then locks the exact nonrevoked certificate. Its authorization
linearization point is the single `clock_timestamp()` sampled after all
locks are acquired and compared with the persisted certificate validity window.
It does not use the transaction-start timestamp, which could accept a leaf that
expired while waiting for an administrative lock.

The operator guard locks the matching active operator and tenant. The successful
locked-row match is its authorization linearization point. Go also verifies the
presented TLS leaf's validity. Revocation, certificate replacement and role
changes cannot commit while a successful authorization transaction still holds
the corresponding shared locks.

Calling either function in autocommit mode and later opening an unrelated
mutation transaction does not close the race. The caller must keep authorization
and mutation on the same transaction/connection, commit before returning success,
and roll back failures, cancelled requests and panics. Read bounded HTTP bodies
before opening the transaction so a slow client does not prolong authorization
locks. This database interface does not by itself prove that a particular HTTP
handler follows those requirements.

The database remains a trusted backend boundary. Function parameters identify
the tenant, endpoint and operator authenticated by Go. Shared backend credentials
do not independently prove an individual caller's mTLS identity inside
PostgreSQL. A compromised backend credential can invoke permitted functions for
existing principals. This design blocks direct identity rewrites, direct result
insertion and direct audit edits; it does not claim isolation from complete
backend compromise or cryptographic audit tamper resistance.

Apply future schema changes with a controlled migration role, explicitly revoke
public execution when creating new functions, review changes to the operation
allowlist, and run bootstrap/privilege regression against the changed candidate.
Do not add broad table writes to make a new operation work.

## Executable regression

Run from the repository root against an empty disposable PostgreSQL database
whose name begins with `edr_`, using a fixture administrator:

```sh
EDR_TEST_DATABASE_URL="$EDR_DISPOSABLE_ADMIN_CONNECTION" \
  bash scripts/test-runtime-privileges.sh
```

The shell script accepts loopback TCP only, refuses existing EDR schema tables,
and permits the CI candidate's `edr_ci_candidate` ownership marker. It applies
schema 0001–0013, creates unique temporary test logins with an ephemeral
environment-supplied password, applies bootstrap twice and cleans up those
logins. Credential provisioning statements are not echoed; logging of that
fixture credential transaction is suppressed. The script requires an isolated
fixture superuser for role creation and that local logging setting.

The tests use actual separate login connections, not an administrator session
with a superficial role label. They check:

- Exactly eleven definer functions; fixed search paths; correct function owners;
  no public execution; no administrative memberships or object ownership.
- Heartbeat, scheduling, claim, renewal, completion, nested alert/activity
  insertion, assignment, note, state transitions and cancellation.
- Disabled/revoked principals, viewers, cross-tenant operations and result replay.
- Thirty-five denied runtime operations, including trust-field changes, direct
  result/activity insertion, trigger disabling, DDL, role escalation,
  administrative function execution and lease-secret reads.
- Seventeen denied registry operations while both identity lookups succeed using
  a readonly connection.
- Seven deterministic two-session schedules, automatically run by
  `scripts/test-certificate-authorization-races.sh`: certificate revocation,
  certificate rotation and operator-role change each run with authorization
  first and administration first. A seventh test holds an unchanged certificate
  row until it expires after the authorization transaction has begun.
  Each schedule requires an observed PostgreSQL lock wait and explicit FIFO
  release; final mutation counts distinguish accepted from denied transactions.
- Eight lease timing schedules require an observed lock wait: five expired-lease
  rejections, two full-duration lease grants after authorization waits, and
  fresh-time recovery that skips a concurrently locked job.
- Migration 0013 is reapplied after an obsolete-function fixture and preserves
  function OIDs, ownership, ACLs, security modes and local settings. Its admin-owned
  `edr_schema_capabilities` record is read-only for both serving roles; attempts
  to insert, update or delete it are denied.

For databases already at 0012, apply only the versioned 0013 upgrade and then
reapply this bootstrap in the approved maintenance window. The upgrade replaces
the five lease functions atomically and records `scan_lease_wallclock` version 1.
Both bootstrap and service startup require that capability. A modified historical
migration file alone does not update an existing installation. Retain the approved
backup and verify compatibility before starting the service.

These are PostgreSQL privilege and protocol tests. They do not execute ClamAV,
prove actual Windows/Linux host behavior, sign installation packages, approve
deployment or establish production readiness.

## PostgreSQL references

- [PostgreSQL 16 SELECT privileges and locking](https://www.postgresql.org/docs/16/sql-select.html)
- [PostgreSQL 16 safe SECURITY DEFINER functions](https://www.postgresql.org/docs/16/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY)
