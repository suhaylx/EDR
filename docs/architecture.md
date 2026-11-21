# TuranSec EDR: initial architecture and implementation milestones

## Security core

ClamAV official signatures are the first signature baseline. The proprietary static analysis layer will inspect PE/DLL and ELF metadata safely, without executing unknown files on endpoints. A clean ClamAV result is not a safe verdict. Confirm real DLL module loading separately from file creation, linking module path/hash/signer to the loading process and parent lineage. Later use isolated, disposable dynamic-analysis sandboxes only with tenant approval.

## Separation of failures

Proposed Rust EDR core is independent of the Sysmon manager and collector. Sysmon install and policy update is a separate controlled subcomponent, with verified signed configs, target assignments, old config backup, staged apply, runtime checks, and rollback. Even if Sysmon fails or floods events, ClamAV/scanning, response queue and core heartbeats must continue, subject to measured resource budgets.

## Server / telemetry

Go backend: independent ingestion, control plane and policy management; eventually mTLS device identity, append-only audit, queue and durable data stores. Proposed Postgres control-plane, ClickHouse event storage. Dashboard: React/TypeScript after initial smoke-test UI; must support endpoint groups, policy overrides, deployment jobs, triage, rules and users.

## Enterprise Active Directory

LDAPS provides *directory discovery* not remote software deployment. Discover authorized domains/OUs/computers securely with certificate verification; generate GPO/signed MSI installation plans for authorized admins. Only subsequently integrate an approved runner with narrowly scoped permissions. AD failure must not disable already-installed TuranSec agents.

## Dashboard Sysmon policy design

Immutable versions per Windows/Linux profile. Separate publish from assign and deploy. Precedence: per-agent > selected group > tenant OS default. Show desired and applied revision/hash independently; do not claim an assignment automatically changes remote devices. Staged canary rollouts and audit/rollback are required before production use.
