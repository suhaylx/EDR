# TuranSec EDR — accelerated three-day implementation sprint

**Work packaged:** 2026-11-21 (Asia/Tashkent). **Important:** these are
three *engineering work packages executed in one session*, not evidence that
three calendar days elapsed, three deployments occurred, or review gates passed.

Repository: `suhaylx/EDR`, private. All work is **draft and stacked** on
the unmerged BE-141–145 branch (PR #145). No merge to `main`, no
production listener, no Windows/Linux endpoint rollout, no quarantine or
deletion.

## Day 1 — Restore SOC control-plane routing

**Draft PR [#149](https://github.com/suhaylx/EDR/pull/149)**

- Fixed `SOCScanHandler` using `operation` before declaration, so the
  authenticated SOC read and malware-alert subroutes can compile.
- Removed unused `encoding/json` import from alert route handler.
- Added top-level router tests for authenticated scheduling, scan summary,
  alert feed, alert statistics, acknowledge, no-store and viewer denial.

Acceptance remains **not verified** by CI until a runner executes
`go test ./...` and `go vet ./...`.

## Day 2 — Endpoint inventory and investigation

**Draft PR [#150](https://github.com/suhaylx/EDR/pull/150)**

Implemented behind the separate **SOC operator TLS 1.3/mTLS listener**:

- `GET /soc/v1/tenants/{tenant}/endpoints` — platform/health filters and
  bounded paging (1–100).
- `GET /soc/v1/tenants/{tenant}/endpoints/{agent}` — current device
  heartbeat, scanner readiness and reported versions.
- `GET /soc/v1/tenants/{tenant}/endpoint-stats` — fleet counts by
  Windows/Linux and online/degraded/stale/unseen/revoked.
- `GET /soc/v1/tenants/{tenant}/endpoints/{agent}/timeline` —
  bounded per-device scan-job and malware-alert timeline.

Freshness uses **PostgreSQL server time** with a 5-minute heartbeat window.
`online` and `scan_ready` are observational device telemetry, not a
device-trust/anti-tamper attestation. Results do not expose lease tokens,
client certificate material, raw database errors or other tenants' data.

## Day 3 — Analyst case management and immutable activity

**Draft PR [#152](https://github.com/suhaylx/EDR/pull/152)**

- Migration `0012_soc_alert_activity.up.sql` creates a tenant/alert-scoped
  append-only activity table and extends alert assignment/actor attribution.
- `GET .../my-alerts`: list the authenticated operator's assigned,
  unresolved alerts (caller cannot substitute a different assignee).
- `POST .../alerts/{uuid}/assign`: assign/unassign open or acknowledged
  alerts to active same-tenant scanner operators.
- `POST .../alerts/{uuid}/notes`: append a bounded, attributed
  investigation note and return activity UUID.
- `GET .../alerts/{uuid}/activity`: paginated audit history including
  creation, assignment, note, acknowledge, resolve and reopen.
- Existing alert list/detail includes `assigned_to`.
- Disposable PostgreSQL regression `scripts/test-soc-case-audit.sql` and
  top-level Go handler/negative tests are added; the ordered migration
  chain and path triggers now include migration 0012.

**Audit limitation:** a database superuser or compromised privileged
migration role could bypass triggers. This is an append-only application
record with role enforcement, **not** cryptographically tamper-proof evidence.

## Current verification status

| Gate | Evidence / current status |
| --- | --- |
| Last known working CI baseline | PR #138, 8 applicable workflows passed |
| New sprint PR #149 | Actions run `44934960448`: failed before any runner assigned (`runner_id=0`, `steps=[]`) |
| New sprint PR #150 | Actions run `44934965848`: same pre-runner failure |
| Day 3 PR #152 | GitHub CI not verified on exact final head |
| PostgreSQL 16 migration 0012 | SQL test committed; not verified executed |
| Go build/test/vet | Tests committed; not verified executed on final head |
| Rust Linux/Windows | No successful final-head CI |
| Operator CA/role provisioning | Not deployed; independent InfoSec review required |
| Real ClamAV Windows/Linux lab | Not performed |
| Merge / release | **Not performed** |

An Actions failure with `runner_id=0` and no steps is a **CI execution
blocker**, not a compiler/test failure. It is **not** a pass either. There
may still be source/test defects when runners become available.

## Hand-off and blockers

- [DEVOPS P0 #153](https://github.com/suhaylx/EDR/issues/153):
  investigate GitHub-hosted Actions policy, quota/billing and runner
  assignment; rerun exact-head checks with logs.
- [QA P0 #154](https://github.com/suhaylx/EDR/issues/154):
  PostgreSQL migrations 0001–0012; Go tests/vet; Rust Ubuntu/Windows;
  real certificate/tenant/revocation and isolated ClamAV workflow.
- [SEC P0 #155](https://github.com/suhaylx/EDR/issues/155):
  trust anchors and operator certificate roles, least-privileged
  PostgreSQL grants, cross-tenant authorization, and audit semantics.

### Remaining acceptance blockers

1. All stacked PRs reviewed/updated to a consistent candidate branch
   after independent CI runs; don't treat multiple green bases as
   permission to merge all PRs.
2. Agent 1 approves mTLS CA and key management, PostgreSQL least-privilege
   grants and non-destructive alert handling. Agent 3 QA independently
   exercises abuse cases and captures logs.
3. Controlled Windows Server 2022 and Ubuntu 24.04 lab installation,
   ClamAV 1.5.5 scan (benign, EICAR, timeout/error), offline retry and
   revocation behavior tested without touching live endpoints.
4. SOC interface integration, case retention/export policy, signed binaries
   and rollback/monitoring before any canary.
