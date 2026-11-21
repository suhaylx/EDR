# Independent functional QA — remaining Days 4–7 candidate

**Functional engineering verdict: APPROVE for the exercised workflows. Full acceptance: NOT APPROVED. Release: NO-GO.**

Candidate: [`90233f26e3e93b2d777cf1e07ca6f2fd479f5b82`](https://github.com/suhaylx/EDR/commit/90233f26e3e93b2d777cf1e07ca6f2fd479f5b82), tree `6f2272b81541dd3efaaab73c6327a44d8c42d2b3`, [PR #180](https://github.com/suhaylx/EDR/pull/180). Release-file label: `v0.1.0-rc.1`.

This is a fresh independent functional QA review. Its scope is the compiled SOC client, installation/package behavior, configuration compatibility, command-line operation and executed regression evidence. I did not edit candidate source, publish GitHub comments, merge, install a service on a deployment host or deploy. The requested additional InfoSec review was stopped by automatic security filtering, as reported by root; this functional review does not retry or replace that audit and provides no InfoSec approval. It also does not represent the original Agent 3 owner verdict or completion of all original engineering assignments.

## Exact source and independence

I independently fetched the GitHub commit and PR metadata. PR #180 points to this exact SHA and remains an unmerged draft. I tested a private clean checkout, verified the local Git commit object's hash, recorded the full tree identity and SHA-256 hashes of all 360 tracked files, and confirmed the checkout remained clean after the checks. `final-source-manifest.json` also hashes the six reviewer-owned harnesses.

All results in the main table below were executed after the published freeze. Earlier working-copy observations are retained separately. The final SOC client was compiled from the candidate's actual TypeScript files, including final `soc-api.ts` hash `60ce4fed6248639a4f9fd6eef9896233bb60661b83e30f0b448fd07933492f5c`. The final backend includes the small typed-nil signer guard integrated from the owner's PR; ordinary build/test/race/vet passed with that delta. Root's recorded pre-fix constructor panic and post-fix regression were inspected with their attribution preserved.

## Independently executed results

| Workstream | Actual result | Evidence |
|---|---|---|
| Go build, tests, race detector and vet | PASS; all five mandatory ledger commands exit 0 on the exact SHA | `final-candidate/.quality-evidence/backend-linux.json`, `final-backend.log` |
| React dependency installation, typecheck, tests and production build | PASS; **374 tests passed**, zero failures, locked dependencies installed; browser execution is excluded from this functional subset | `final-frontend.json`, `final-frontend.log` |
| Compiled SOC API client with real Go/PostgreSQL | PASS; **10 checks, eight single POSTs** cover acknowledgement, notes, assignment, unassignment, resolution, reopening, path-scan scheduling and cancellation | `final-soc-client-functional.log`, `soc-client/source-manifest.json` |
| Linux installer and launcher | PASS; **36 tests**, including real filesystem staging, real three-unit systemd parsing and four actual TLS 1.3 loopback probe fixtures; service-manager actions use an explicit fixture implementation | `final-release-tools.log`, mandatory release-tools ledger |
| Other release tooling | PASS; **12** signature/rollback primitive tests, **8** host-evidence collector tests and **8** release-preparation tests | Same release-tools ledger and log |
| Independent ordinary CLI workflows | PASS; dry-run creates no installation directory, staging does not select/start a service, repeat staging reports its state, packaged-layout help/imports work, platform-combined metadata and checksums work in paths containing spaces | `final-installer-cli.log`, `final-prepare-cli.log` |
| Actual built Linux archive | PASS; all **38 files** match the independently pinned manifest; both actual executables report the complete candidate SHA; documentation links/config paths, 13 migrations, helper CLIs and temporary staging work | `final-actual-package.log` |

The real SOC functional fixture uses the actual Go service and PostgreSQL, temporary mTLS credentials and the compiled frontend API client. It checks the returned case state, optional scan-result handling, job summaries and persisted activity after each operation. A separate administrative SQL read confirms exactly two jobs exist and the newly scheduled job is cancelled. The detection used to seed the case is explicitly synthetic. The transport adapter exercises the API client over real HTTPS; it does not emulate browser certificate selection, keyboard interaction or accessibility.

The installer tests execute real file operations and unit parsing. The four probe tests use a temporary TLS server, not the EDR application or an installed systemd service. These tests substantiate implementation behavior while leaving native service acceptance and live rollback open.

## Functional findings and corrections

The new service launcher initially rejected valid dotted enrolled identities such as `linux.01`, while accepting 97–128-character IDs unsupported by the existing Rust/Go contract. I independently reproduced both outcomes and sent the finding to the installer owner. The final implementation accepts the existing ASCII dot/underscore/hyphen identity format up to 96 characters and rejects unsupported lengths and dot-only IDs. Both its regression and the separate reviewer recheck passed. The real Go/PostgreSQL client fixture also uses `linux.01` successfully.

The release instructions initially described packages as reproducible without repeated-build byte-identity evidence. That wording was corrected to a package built from one exact source commit. The final documentation matches the package's migration/bootstrap paths, separate registration and activation commands, credential configuration, bounded endpoint scheduling and preserved-data removal behavior. The secure SOC instructions now describe the implemented scanner-role controls and viewer-role reads.

No unresolved ordinary functional defect was found in the exercised final paths. This statement is limited to the tested paths and scope.

## Actual release file checked

Archive: `turansec-edr-90233f26e3e9-linux-x86_64-unsigned.tar.gz` — **10,741,228 bytes**.

- Archive SHA-256: `f70c3fc435b2d2e7dc96346bed14ac6546335824b2d1a7b45598acfe051e3fcc`
- Manifest SHA-256: `f70aa9ae5e64f7a94acfe7abc3174c1ea5aaf267eaa717f64f318a13f0d43825`
- Source: `90233f26e3e93b2d777cf1e07ca6f2fd479f5b82`
- Publisher signature: **absent**
- Windows package: **not built**

I validated the original manifest pin independently of the package's internal verifier, compared every extracted file's size and SHA-256, ran both real packaged `--version` commands, checked the installation-document links and CLI imports, and exercised both dry-run and actual staging under a disposable temporary prefix. No service was selected, started or enabled. I then used the packaged release helper on a temporary copy and validated its generated checksums; it correctly retained Windows as an absent platform and deployment authorization as not granted.

## Other evidence inspected

Root's separate exact-SHA PostgreSQL, seed/restart verification and ten-check Go/PostgreSQL/Rust/React-assets integration ledgers all report PASS with command exits 0. I inspected these records and preserve their attribution as root-executed evidence. They do not replace the independent compiled-client test above or establish browser, deployment-host or real scanner acceptance.

I independently fetched [exact-head candidate-ci run 44946276402](https://github.com/suhaylx/EDR/actions/runs/44946276402). All eight jobs failed with no recorded steps. Root's corresponding raw GitHub readback additionally records `runner_id = 0` for every job, which I inspected. Local results do not satisfy successful GitHub CI execution.

## Unwaived acceptance and release gates

1. **GitHub CI:** exact-head workflow execution remains failed before a runner/steps are recorded.
2. **Browser and native Rust:** actual browser tests remain unexecuted; the required frontend gate fails installing browser dependencies. Root's exact-SHA Rust gate records 59 passed, one genuine Unix-socket `EPERM` failure and zero ignored tests. No Windows native pass is credited.
3. **InfoSec and owner verdicts:** the additional InfoSec review remains unapproved following its automatic filtering stop. This functional review supplies no replacement approval. Original role-owner sprint acceptance remains separate.
4. **Deployment hosts:** actual approved Ubuntu and Windows Server 2022 installation/start/stop/restart/reboot/offline/resource acceptance, real scanner/ClamAV/EICAR and Sysmon evidence remain outstanding. The local TCP/temporary filesystem results do not fulfill those records.
5. **Signed release and live rollback:** this Linux artifact is unsigned; no organizational signer or Windows Authenticode result is established. Native installed-service rollback and database restore still require the approved hosts and compatibility plan.
6. **Deployment authorization:** the named owner must approve the exact signed package, targets, canary, window and validated rollback. No such authorization is provided by this review.

The exercised candidate's ordinary functional behavior is approved at the recorded SHA. **Full acceptance remains NOT APPROVED and the current release decision is NO-GO.**
