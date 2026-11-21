# TuranSec EDR — Agent 2 / Agent 3 code review, 21 November 2026

**Scope:** stacked backend/Rust/SOC functionality through accelerated sprint
draft PRs #149/#150/#152; separate QA evidence PRs #144/#146/#156.

**State:** fixes committed to [PR #159](https://github.com/suhaylx/EDR/pull/159).
No new code has passed a real runner; the repository remains **NO-GO** for
merge, release, any operator listener exposure, or Windows/Linux endpoint
deployment. An Actions `failure` with `runner_id=0` and `steps=[]` is
a failure of CI execution, not a source-test failure **or** a PASS.

## Findings and fixes

| ID | Severity | Review finding / change | Outcome |
| --- | --- | --- | --- |
| QA-01 | P1 | Go `ChangeSOCAlert` used substring membership: `ack\|resolve` passed the Go-level action check, although SQL denied it. | Fixed: exact `ack/resolve/reopen` whitelist; table-driven tests |
| QA-02 | P1 | HTTP/DB control-text mismatch and terminal/bidirectional-display spoofing in notes, scan paths, scanner metadata and heartbeat versions. | Fixed: shared unsafe-text guard, negative and positive unit tests |
| QA-03 | P1 | Single `Read` incorrectly treated a legal `(0,nil)` result as an empty request body, potentially allowing delayed bytes on claim/cancel/ack/reopen. | Fixed: bounded full read; zero-then-data fake Reader regressions |
| QA-04 | P0 | Client certificate/role/fingerprint revocation and tenant route denial must be proven over real TLS. | Added ephemeral TLS 1.3 integration tests; not yet executed on final SHA |
| QA-05 | P0 | Agent mTLS downgrade/trust-root/forged-header denial. | Integrated QA Agent 3 test from #144; not yet executed |
| QA-06 | P0 | Single-use enrollment challenge and anti-replay must survive real PostgreSQL restart. | Integrated QA Agent 3 disposable PG16 restart suite from #146; not yet executed |
| QA-07 | P0 | Certificate rotation must serialize with concurrent tenant disablement. | Source already has `FOR UPDATE OF a FOR SHARE OF t`; imported QA #156 positive lock-wait race regression |
| QA-08 | P0 | GitHub Actions jobs fail **before** runner assignment, regardless of source change. | NOT FIXED; possible owner billing/budget/runner-policy issue; DEVOPS #153 / QA #148 |
| SEC-09 | P0 | Independent operator CA trust, Windows private-key ACLs, least-privilege DB role grants, audited operator provisioning. | Not approved/provisioned; InfoSec #155 |
| QA-10 | P0 | PostgreSQL 0001–0012, Go test/vet/race, Rust Linux/Windows and real isolated ClamAV scans on lab endpoints. | NOT VERIFIED; independent QA #154 |

### Evidence of the CI execution blocker

- Known previously working [Actions run 44933506839](https://github.com/suhaylx/EDR/actions/runs/44933506839)
  had runner IDs and executed Go/Rust steps.
- Recent [run 44935151910](https://github.com/suhaylx/EDR/actions/runs/44935151910)
  had `runner_id=0`, no steps, and zero billed Ubuntu compute time.
- [QA Agent 3 issue #148](https://github.com/suhaylx/EDR/issues/148)
  independently reports the same symptoms on unrelated test-only PRs
  #144/#146/#147/#156.
- Related GitHub documentation:
  https://docs.github.com/en/actions/how-tos/troubleshoot-workflows
  recommends checking Actions billing failures and budgets.
  This pattern is **not proof of a billing hold for this account**.
  The repository owner must inspect the job-start annotation and
  `Settings > Billing and licensing > Usage / Budgets / Payment information`.
  If no hold exists, use GitHub Support with these run IDs.
- Do not make this security repository public or install a non-vetted
  self-hosted runner to evade Actions minutes.

## QA reproduction order (disposable lab only)

1. Once GitHub Actions starts assigning a runner, confirm workflow logs
   have actual executed steps, not just green/shallow metadata.
2. `cd backend && go test ./... && go test -race -count=1 ./... && go vet ./...`
3. `cargo test --manifest-path agent/Cargo.toml --all-targets` and
   `cargo check --manifest-path agent/Cargo.toml --all-targets`
   on Linux and Windows.
4. Run `.github/workflows/postgres-migration-chain.yml` against an EMPTY,
   dedicated PG16 CI database; verify migrations 0001–0012 and
   `scripts/test-soc-case-audit.sql`.
5. Run the PostgreSQL certificate rotation workflow with
   `scripts/test-certificate-rotation-tenant-race.sh` and the
   PostgreSQL enrollment challenges workflow with
   `scripts/test-enrollment-challenge-db-restart.sh` seed/actual service restart/verify.
   Both scripts are authorized for **disposable CI databases only**.
6. Confirm API and registry tests for:
   missing/untrusted/wrong-EKU client certificate, TLS 1.2 downgrade,
   revoked and wrong-fingerprint operator, viewer denied mutations,
   tenant/device isolation, malformed and delayed payloads, and
   positive authorized assignment/notes through the top-level router.
7. Independent Agent 3 QA and Agent 1 InfoSec approval on the **same exact**
   candidate commit, signed packaging and rollback plan, then
   separately approved Ubuntu/Windows lab deployment and
   clean/EICAR/error ClamAV 1.5.5 validation.

## Security limitations beyond this review

The append-only SOC activity trigger is not a cryptographically signed
tamper-proof audit ledger. PostgreSQL table owners or privileged maintenance
roles may bypass triggers; permissions, backups and forensic export policies
need approval. Endpoint PING/heartbeat is *reported liveness*, not host
attestation. A real signed Windows service, secure private-key storage,
full process/Sysmon telemetry and production response actions are not
delivered by these draft PRs.

No user credentials, certificates, customer files or live hosts were used
during this review. No merges, deployments, quarantines or deletions.
