# TuranSec EDR — remaining Days 4–7 evidence

Recorded 22 November 2026, Asia/Samarkand. Source candidate:
[`90233f26e3e93b2d777cf1e07ca6f2fd479f5b82`](https://github.com/suhaylx/EDR/commit/90233f26e3e93b2d777cf1e07ca6f2fd479f5b82),
tree `6f2272b81541dd3efaaab73c6327a44d8c42d2b3`, [PR #180](https://github.com/suhaylx/EDR/pull/180).

**Functional engineering QA: APPROVE for the exercised workflows. Full acceptance:
NOT APPROVED. Deployment/release decision: NO-GO.** The seven-day sprint continues
from its three-day baseline; these records do not declare the remaining four days
or the original four engineering assignments complete.

## Generated release file

[Download the Linux archive](https://github.com/suhaylx/EDR/raw/a756b0761454221e907f7f9612c7be298a0d1af6/turansec-edr-90233f26e3e9-linux-x86_64-unsigned.tar.gz)
from the immutable [release-file commit](https://github.com/suhaylx/EDR/tree/a756b0761454221e907f7f9612c7be298a0d1af6).
The package is labelled `v0.1.0-rc.1`, contains 38 files and is **unsigned**.
It is 10,741,228 bytes. No Windows archive was built.

| Identity | SHA-256 |
|---|---|
| Archive | `f70c3fc435b2d2e7dc96346bed14ac6546335824b2d1a7b45598acfe051e3fcc` |
| Manifest | `f70aa9ae5e64f7a94acfe7abc3174c1ea5aaf267eaa717f64f318a13f0d43825` |

The package was built from a committed-tree export. Both native ELF x86_64 binaries
execute `--version` and identify the complete candidate SHA. Independent QA checked
all archive file sizes/hashes, 13 migrations, document/config paths, helper CLI
imports, dry-run and actual temporary staging, and generated release checksums.
See [package readback](package/release-v0.1.0-rc.1-readback.json) and
[independent actual-package execution](qa/final-actual-package.log).

## What changed

- The authenticated React SOC now exposes existing backend path-scan scheduling,
  job/result reads, pending cancellation, acknowledgement, case notes, assignment,
  resolution and reopening. Viewer sessions remain read-only. Mutations recheck
  session/target state, send one POST, and distinguish uncertain outcomes from
  accepted operations whose authoritative reload failed.
- Linux tooling now verifies and stages versioned packages, registers systemd
  units, activates with authenticated health and selected-process verification,
  performs upgrade/failure recovery, and preserves data/credentials on removal.
  The existing Rust commands run as bounded oneshot batches under a timer.
- Release preparation records source/platform/archive identities, checksums and
  notes. A manual GitHub workflow builds native candidates and can attach files
  to an explicitly requested draft when actual runners are available.
- The installation manual now covers those operations. The newest Agent 1
  keypair PR's typed-nil signer case is integrated into the existing stronger
  constructor validation; its actual pre-fix panic and corrected regression are
  retained with implementation attribution.

## Actual exact-source execution

| Required area | Observed result | Evidence |
|---|---|---|
| Go build, tests, race and vet | PASS locally, independently repeated by QA | [Root ledger](execution/backend-linux.json), [QA log](qa/final-backend.log) |
| PostgreSQL 16 migrations, restricted identities and concurrency | PASS; 35 runtime and 17 registry forbidden operations denied; seven authorization and eight lease timing checks passed | [Ledger](execution/postgres-linux.json), [SQL execution](execution/final-postgres.log) |
| Actual database restart/persistence | PASS after stopping and restarting the test PostgreSQL process | [Seed](execution/postgres-seed-linux.json), [post-restart verification](execution/postgres-verify-linux.json) |
| Go/PostgreSQL/Rust/React assets | PASS, 10 actual integrated checks | [Integration result](execution/integrated-candidate.json), [execution ledger](execution/integration-linux.json) |
| React functional checks | PASS: 374 tests, typecheck and production build; independently repeated | [QA frontend record](qa/final-frontend.json), [log](qa/final-frontend.log) |
| Compiled SOC client against actual Go/PostgreSQL/mTLS | PASS, 10 independent checks covering eight single-POST workflows, with SQL readback | [Independent execution](qa/final-soc-client-functional.log), [harness](qa/check_soc_client.mjs) |
| Release/installer tools | PASS: 12 signature/rollback, eight collector, eight release-preparation and 36 installer tests | [Ledger](execution/release-tools-linux.json), [independent log](qa/final-release-tools.log) |
| Rust native gate | FAIL: 59 passed, one Unix-socket EPERM failure, zero ignored | [Ledger](execution/rust-linux.json), [log](execution/final-rust.log) |
| Actual browser gate | BLOCKED: dependency installation failed; browser tests did not execute | [Ledger](execution/frontend-linux.json), [log](execution/final-frontend.log), [capability report](BROWSER_CAPABILITY_REPORT.md) |
| GitHub exact-head CI | FAIL before runner assignment; all eight candidate jobs have runner ID 0 and no steps | [Raw selected fields](github-exact-head-ci.json), [run 44946276402](https://github.com/suhaylx/EDR/actions/runs/44946276402) |

The integrated detection seed and API-client case seed are synthetic. The tests
do not establish real scanner-to-SOC or deployment-host acceptance. Installer
lifecycle tests use a simulated service manager with real file operations; unit
parsing and TLS health fixtures do not establish a live systemd installation.
Neither failed gate was waived, skipped, or relabelled as passing.

## Independent review and original owner state

Read [the full independent functional QA verdict](qa/FINAL_FUNCTIONAL_QA.md) and
[machine-readable evidence record](qa/FINAL_FUNCTIONAL_QA.json). QA used its own
clean checkout and independently checked the canonical GitHub identity. The
report distinguishes independently executed checks from inspected root logs.

The additional independent InfoSec review was stopped by an automatic security
filter. It remains **unapproved**. The functional QA review did not retry or
replace that security audit. A prior candidate's engineering review is not
approval of this follow-up source.

The original owner issues [#1](https://github.com/suhaylx/EDR/issues/1),
[#2](https://github.com/suhaylx/EDR/issues/2),
[#3](https://github.com/suhaylx/EDR/issues/3) and
[#4](https://github.com/suhaylx/EDR/issues/4) remain open. The latest inspected
Agent 1 owner statement on [PR #181](https://github.com/suhaylx/EDR/pull/181)
is explicitly NO-GO/DRAFT. Drafts, local engineering approval and predecessor
green CI do not satisfy the original all-four completion condition.

## Real ClamAV adapter observation, with attribution

The [earlier scanner probe](scanner-adapter/README.md) exercised the unchanged
Rust adapter against actual ClamAV 1.5.5 with vendor-verified daily/bytecode
databases: benign returned clean-by-signature, EICAR returned its signature
match, and stopped clamd produced a connection failure with no clean verdict.
[Source-blob mapping](scanner-adapter/NEW_CANDIDATE_MAPPING.json) confirms those
modules and lockfiles are unchanged in this candidate.

This was a separate TCP adapter probe, not the Linux product Unix-socket command,
not a new run of this release binary and not a full Go/PostgreSQL/SOC detection
pipeline. The complete vendor database set was unavailable. No native Windows
or designated Ubuntu host pass is claimed.

## Remaining four-day acceptance work

The current [Days 4–7 checklist](https://github.com/suhaylx/EDR/blob/90233f26e3e93b2d777cf1e07ca6f2fd479f5b82/docs/sprints/REMAINING_DAYS_4_7.md)
retains the uncompleted gates: restore actual GitHub runner allocation; execute
browser and native Windows/Linux checks; exercise installed services, real
scanner/Sysmon paths, restart/offline/resource behavior and database recovery;
obtain current InfoSec and original owner approvals; sign with the approved
organizational publisher; and obtain deployment authorization for exact files,
hosts, canary, window and rollback plan.

The connector does not expose runner/account administration routes, and its
browser fallback is signed out of the private repository. The authorized native
hosts remain unreachable from this environment. There is no approved signing
identity here. These facts are execution/access blockers, not evidence of a
specific billing cause. Main was not merged, and no deployment host was changed.

The source and unsigned file are available for review. They do not establish a
feature-complete enterprise EDR, complete all four sprint assignments, or grant
production readiness.
