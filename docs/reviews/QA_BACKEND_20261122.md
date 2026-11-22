# Backend and endpoint QA — 22 November 2026

## Decision and scope

**The exercised merge-baseline checks pass. The new QA isolation regressions pass after correction. Full installed-system acceptance remains NOT APPROVED.** The enrollment-expiry migration and its live PostgreSQL race suite require a fresh successful candidate run before their runtime behavior is accepted.

This independent engineering QA pass reviewed merged source `f00cab502cf04ee92fed1210fb7ba295d92e9c36`, exact GitHub job execution, the PostgreSQL harness, integrated Go/Rust/PostgreSQL boundaries, and disposable-database target guards. It does not supply the original role owner's approval or authorize deployment.

The merged tree is `072fcd9d483aee90addddc9801f56b754285516d`, identical to the tree of earlier candidate `65702cbc1cde6750304d9e438bb27bc0537c2d45`. Earlier candidate execution remains attributed to that earlier commit; tree equality is not described as another execution on the merge commit.

## Findings and corrections

### QA-20261122-01 — inherited libpq routing could bypass local-only test guards

**Severity: medium; scope: destructive QA harness isolation.** `scripts/ci/candidate-postgres.sh`, `scripts/test-integrated-candidate.py`, and `scripts/test-soc-endpoint-inventory-sql.sh` checked a loopback host/URI but permitted inherited `PGHOSTADDR`, `PGSERVICE`, and `PGSERVICEFILE`. `test-runtime-privileges.sh` already rejected these settings, but its check ran after earlier candidate database operations.

PostgreSQL documents that `hostaddr` controls the network destination when both `host` and `hostaddr` exist, and that `PGHOSTADDR` supplies the default `hostaddr`. Therefore a loopback URI alone does not prove the client will connect to loopback. See the [PostgreSQL 16 connection parameters](https://www.postgresql.org/docs/16/libpq-connect.html#LIBPQ-PARAMKEYWORDS) and [environment-variable documentation](https://www.postgresql.org/docs/16/libpq-envars.html).

All three entry points now reject inherited routing overrides before the first client operation. The URI guards also reject whitespace/control characters before URL parsing can normalize them. Existing dedicated database-name, explicit opt-in, loopback, and port checks remain in force.

`scripts/test-qa-db-targets.py` reproduces the guard weakness without a database or network: shell clients only record invocation and exit; the Python integration and new enrollment-race harnesses' first SQL calls are replaced with a sentinel exception. The unchanged three existing entry points fail the new suite; the corrected files pass all eleven test groups, covering 28 target cases across four entry points. The new harness/runner are held equal in the before/after comparison. Tests prove refusal occurs before client invocation, not merely that an attempted connection fails. The candidate PostgreSQL job now requires this suite.

### QA-20261122-02 — main pushes did not execute the full candidate pipeline

**Severity: medium; scope: verification coverage.** The merge triggered only `starter-ci`; `candidate-ci.yml` had `pull_request` and `workflow_dispatch` triggers. The merged source therefore had fresh Go/Rust/auth-session checks but no fresh full candidate execution on that merge SHA.

The proposed workflow adds `push` for `main`, while retaining both existing triggers and every aggregate dependency. Once merged through normal review, future main pushes will exercise PostgreSQL, native Windows Rust, integrated services, browser/accessibility, and release-tool checks as well. This workflow change does not retroactively produce a run for `f00cab502cf0`.

### Enrollment-expiry correction coordination

InfoSec identified transaction-start clock checks in enrollment/challenge/rotation paths. This QA patch wires the additive `0014_enrollment_wallclock.up.sql` into the full migration chain and restricted-role suite, and adds a dedicated fresh database for `scripts/test-enrollment-wallclock-races.py`. Independent source review confirmed that the migration acquires tenant/challenge/old-certificate locks before reading the clock, validates the new certificate before challenge consumption or old-certificate revocation, and restores function metadata without adding grants.

QA supplied `scripts/test-enrollment-wallclock.sql`: valid and rejected identity/digest/platform/certificate-window inputs, challenge and certificate replay, unchanged challenge/agent/certificate/audit state after denials, and atomic successful enrollment/rotation. Its upgrade fixture deliberately replaces current clocks with obsolete ones, then applies 0014 twice while checking OID, owner, nontrivial ACL, one definer/two invoker modes, and function-local settings. Temporary role/definition changes are restored in the dedicated fixture database. These SQL assertions still require hosted execution.

The coordinating engineer's Python runner is source-reviewed for three historical stale-transaction controls and twelve corrected timing/authorization schedules. It requires an observed transaction/lock wait before releasing the fixture and checks unchanged stored state after denial. Integrated service startup and privilege bootstrap now also have dedicated missing-capability/version-2 rejection tests, using capability-specific diagnostics so unrelated startup errors cannot satisfy the regression. These live checks remain pending fresh candidate CI.

## Executed and inspected evidence

| Evidence | Actual result | Attribution |
| --- | --- | --- |
| [Merged-main starter CI](https://github.com/suhaylx/EDR/actions/runs/44973951768) | All three jobs succeeded. Go tests, uncached race tests, and vet passed; Linux Rust reports 60 passed, zero failed/ignored; UI auth-session passed. | Exact `f00cab502cf04ee92fed1210fb7ba295d92e9c36`, run attempt 1. Job logs were independently inspected. |
| [Earlier full candidate PostgreSQL job](https://github.com/suhaylx/EDR/actions/runs/44951109428/job/136989003166) | Actual restricted logins denied 35 runtime and 17 registry forbidden operations; observed lock schedules and real postmaster restart passed. | Earlier `65702cbc1cde6750304d9e438bb27bc0537c2d45`; same tree, not fresh merge execution. |
| [Earlier integrated candidate job](https://github.com/suhaylx/EDR/actions/runs/44951109428/job/136989003115) | 10 of 10 integrated checks passed. | Earlier source; real service/DB/Rust transport and synthetic scanner-result fixtures. No real ClamAV detection claim. |
| [Earlier native Windows Rust job](https://github.com/suhaylx/EDR/actions/runs/44951109428/job/136989003093) | 48 passed, zero failed/ignored. | Earlier source on Windows CI, not installed Windows Server 2022 acceptance. |
| New database-target regression suite | Baseline exits 1 with 9 failing subtests and 6 errors; corrected working tree exits 0, all eleven groups/28 cases pass. | Fresh local offline execution, no actual database/network. |
| Existing inventory target preflight | Positive and negative target cases passed. | Fresh local execution against corrected script. |
| Existing runtime privilege target preflight | All 27 checks passed. | Fresh local execution. |
| Shell/Python/workflow validation | Changed shell scripts parse; Python compiles; YAML parses and retains all required jobs/triggers; `git diff --check` passes. | Static validation only. |

The new before/after regression record and logs are retained under [backend QA evidence](evidence/20261122-backend/qa-db-target-regression.json). They intentionally identify the baseline commit and mark the corrected working tree as changed; they do not invent a final commit SHA before integration.

## Remaining acceptance requirements

Fresh candidate CI must execute the integrated correction, including PostgreSQL 16 upgrade and lock races. This workspace does not provide a usable Go/Rust/PostgreSQL execution environment: `/usr/bin/go` is not the Go compiler, and Cargo, Rust, PostgreSQL clients/server, and Docker were unavailable in the probed PATH. Those missing tools are recorded as a local execution limitation, not passing checks.

Native Ubuntu 24.04 and Windows Server 2022 installed-service acceptance, real ClamAV/EICAR and genuine Sysmon delivery, Windows service/installer behavior, resource/offline behavior, installed-service/database rollback, approved publisher signatures, original role-owner acceptance, and deployment-owner authorization remain separate requirements. The repository's [host acceptance procedure](../HOST_ACCEPTANCE.md) describes the evidence. No production deployment, host-policy change, signing identity creation, or main-branch merge was performed by this QA agent.
