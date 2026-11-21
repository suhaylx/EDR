# Independent QA review — published TuranSec candidate

**Scoped engineering verdict: APPROVE. Full acceptance: NOT APPROVED. Release: NO-GO.**

This is a fresh independent QA review of [PR #180](https://github.com/suhaylx/EDR/pull/180), commit [`fb0891f98919fd0a166ff10427088f195d208225`](https://github.com/suhaylx/EDR/commit/fb0891f98919fd0a166ff10427088f195d208225), tree `5782837acca162c28d9ceb3dbcca5b7570db2684`. It approves the reviewed implementation and demonstrated local engineering behavior described below. It does not approve the original Agent 3 sprint assignment, satisfy all host acceptance, authorize deployment, or establish production readiness.

## Independence and source identity

I did not edit the integration repository, publish GitHub comments, merge, deploy, or change its tests. I inspected the published commit through the GitHub connector and independently confirmed that PR #180 points to that SHA and remains an open draft. The complete local Git commit object hashes to the same SHA. The clean checkout has 341 tracked files; their SHA-256 hashes and reviewer-owned harness hashes are recorded in `final-source-manifest.json`.

The first full independent PostgreSQL security run used the frozen local commit `99872c8ff16966e007555962c1f824e831a4e20e`. The published commit has the identical complete tree, verified by Git tree IDs and an empty diff. I retained that execution with its actual prepublication attribution. After publication I independently ran the mandatory backend and release-tools ledgers plus all eight reviewer-owned startup/display regressions at the canonical SHA. Root separately reran the full PostgreSQL and integrated candidate ledgers at that published SHA, and I inspected their commands, exit statuses and detailed output. No earlier parent green result substitutes for these records.

Reviewer-owned Go tests live only in `qa-work/reviewer-overlay`; the candidate implementation is unchanged. The positive startup test's development/uncommitted version string is the normal unit-test default, not a claim about a packaged executable; source attribution comes from the verified checkout and manifest. An initial import into the old QA clone lacked the shallow-history metadata required by Go VCS stamping; that failed build is retained in `initial-local-import-backend.*`. A normal depth-one fetch repaired the local checkout metadata, after which the full mandatory backend ledger passed without disabling VCS stamping or any test.

## Independently executed checks

| Check | Result and scope | Evidence |
|---|---|---|
| Exact-SHA Go build, tests, race detector and vet | PASS; all five ledger commands exit 0; source clean before and after | `final-candidate/.quality-evidence/backend-linux.json` and `.log` |
| Real PostgreSQL 16.16 runtime restrictions | PASS; operational lifecycle through actual restricted connections; all 35 prohibited runtime operations and 17 prohibited registry operations denied | `prepublication-privilege-recheck.log` |
| Migration 0013 upgrade and catalog | PASS; obsolete clock bodies replaced; two applications preserve OIDs, owners, ACLs, SECURITY mode and settings; capability marker retained; exact function allowlist and role constraints checked | Same PostgreSQL log |
| Certificate authorization concurrency | PASS; all 7 observed-lock schedules for revocation, rotation, operator-role change and certificate expiry | Same PostgreSQL log |
| Lease timing concurrency | PASS; all 8 schedules, including job-lock and certificate-lock expiry, fresh claim/renew durations and maintenance SKIP LOCKED behavior | Same PostgreSQL log |
| Startup regressions under `-race` | PASS; 6 cases: distinct clusters with identical database names rejected; reissued CAs sharing an SPKI rejected; no-schema DB rejected; valid migrated DB starts and shuts down; old clock/no marker rejected; unsupported marker version rejected | `final-startup-recheck.log`, `final-reviewer-test-results.json` |
| Backend/frontend display regressions under `-race` | PASS; persisted heartbeat U+061C/U+FFFD and BOM-only malicious signature rejected | `final-text-recheck.log` |
| Package/rollback primitives and host-evidence tooling | PASS; 12 signature/tamper/filesystem-switch tests plus 8 collector attribution/safety tests; these are tooling fixtures, not signed release or host acceptance | `final-candidate/.quality-evidence/release-tools-linux.json` and `.log` |

## Findings closed

All concrete initial QA findings are closed in the reviewed scope:

- Database identity compares the explicit canonical loopback host, port and database, with separate registry/runtime users. A same-name database in another local PostgreSQL cluster no longer passes startup.
- Agent and operator trust separation compares signing public keys, so reissued CA certificates cannot disguise use of the same key.
- The Go/Rust/React display contract rejects unsafe controls, invalid replacement text, BOM and blank malicious signatures. The initial fleet-wide rendering failure caused by persisted poisoned heartbeat versions is covered by the regression.
- Startup checks serving privileges, actual schema columns and execution permissions, and requires migration capability `scan_lease_wallclock = 1` on both database handles before binding listeners.
- The install manual and package use the same `backend/migrations/` and `backend/bootstrap/` paths and document the 0001–0012 to 0013 upgrade without rerunning initial schema migrations.

I also reviewed the certificate transaction and wall-clock fixes identified by the separate InfoSec reviewer. Request bodies are bounded and read before locks; the exact verified certificate fingerprint and operator role are authorized inside the same read-committed transaction as mutation; leaf validity is rechecked after authorization waits; failed commit, handler failure and cancellation cannot release a successful buffered response. Lease decisions use fresh wall-clock time after relevant locks. The independent SQL schedules substantiate those database boundaries.

Relevant exact-source files: [startup guards](https://github.com/suhaylx/EDR/blob/fb0891f98919fd0a166ff10427088f195d208225/backend/cmd/edrd/main.go), [transactional certificate authorization](https://github.com/suhaylx/EDR/blob/fb0891f98919fd0a166ff10427088f195d208225/backend/internal/edr/certificate_transaction.go), [SOC application boundary](https://github.com/suhaylx/EDR/blob/fb0891f98919fd0a166ff10427088f195d208225/backend/internal/edr/soc_application.go), [migration 0013](https://github.com/suhaylx/EDR/blob/fb0891f98919fd0a166ff10427088f195d208225/backend/migrations/0013_scan_lease_wallclock.up.sql), [restricted-role bootstrap](https://github.com/suhaylx/EDR/blob/fb0891f98919fd0a166ff10427088f195d208225/backend/bootstrap/runtime_privileges.sql), and [installation manual](https://github.com/suhaylx/EDR/blob/fb0891f98919fd0a166ff10427088f195d208225/docs/INSTALLATION.md).

## Integrated evidence reviewed

Root's published-SHA local integration ledger is PASS, with all executed commands returning 0 and ten explicit acceptance checks. I reviewed both the harness source and resulting evidence. It starts the actual Go/PostgreSQL service with distinct restricted logins, serves built React assets behind operator mTLS, executes real Rust heartbeat and claim/renew/error-result operations, denies TLS/tenant/origin violations, checks malformed heartbeat rejection before persistence, exercises synthetic result-to-alert/case updates, and verifies persisted revocation on reused TLS connections. It explicitly preserves an error when ClamAV is absent. The synthetic malicious result verifies result plumbing only.

The root PostgreSQL ledger and seed/verify phases also pass at the exact SHA. Server start timestamps change from `2026-11-22 00:58:02.94944+05` to `2026-11-22 00:58:41.912325+05`; the post-restart challenge and queue persistence checks pass. The frontend ledger records 326 passed tests, zero failures/skips, typecheck and production build success. Those records are separate from actual browser behavior.

These root-executed records are independently inspected evidence, not represented as executions performed by this reviewer. Their file hashes and attribution appear in `FINAL_QA_VERDICT.json`.

## Unwaived acceptance and release gates

1. **Exact-head GitHub CI remains failed.** I independently fetched [candidate-ci run 44943696845](https://github.com/suhaylx/EDR/actions/runs/44943696845) for the published SHA; all eight jobs return failure with no recorded steps. `final-github-readback.json` preserves that response. Local passes do not convert this into successful GitHub execution.
2. **Native Rust and browser acceptance remain incomplete.** The root Linux Rust gate records 59 passed, 1 failed, zero ignored; the genuine Unix-socket test fails with `EPERM`. The frontend gate fails while installing the locked Playwright browser dependencies. No actual browser accessibility/auth/unknown-state execution is credited. Native Windows execution is not established here.
3. **Actual deployment hosts remain unaccepted.** This review contains no completed authorized Windows Server 2022 or Ubuntu host records, real ClamAV/EICAR execution, verified signature database provenance, genuine Sysmon Event 7 host evidence, native service restart/offline/resource tests, or installed UI acceptance.
4. **Original role-owner acceptance remains separate.** This review is not the original Agent 3 verdict, and the separate fresh InfoSec review is not original Agent 1 owner approval. Four-agent sprint completion must not be inferred from the new candidate or these scoped reviews.
5. **Signing and rollback remain release gates.** Passing signing/tamper fixtures is not an approved publisher signature. An explicitly unsigned portable Linux archive is not a signed installer. Native Windows Authenticode, actual installed-service rollback, and database restore on approved hosts remain required.
6. **Deployment authorization remains outstanding.** A named owner must approve the exact signed package hashes, targets, canary, window and validated rollback. Nothing in this report authorizes deployment.

The engineering candidate is materially more complete and its reviewed startup/trust/storage boundaries have passed meaningful tests. Full acceptance remains unapproved until the listed gates are demonstrated at the same candidate identity. **Current release decision: NO-GO.**
