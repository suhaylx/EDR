# Independent InfoSec review — TuranSec engineering candidate

**Verdict: APPROVE the reviewed source changes for isolated engineering evaluation at commit `fb0891f98919fd0a166ff10427088f195d208225`. Release and deployment remain NO-GO.**

Review finalized after independent GitHub source readback at **2026-11-21 19:58:12 UTC**. No unresolved blocking defect remains within the reviewed engineering scope described below. This is a scoped technical review, not production certification.

This review was performed by the independent InfoSec review agent, separate from the source implementers. The reviewer did not edit or publish repository source. Independent fixtures and execution logs were written only under `infosec-review`. This is not a statement by the original Agent 1, and it does not substitute for that owner's approval of the current sprint assignment.

## Candidate and decision scope

Published candidate: [PR #180](https://github.com/suhaylx/EDR/pull/180), commit [`fb0891f98919fd0a166ff10427088f195d208225`](https://github.com/suhaylx/EDR/commit/fb0891f98919fd0a166ff10427088f195d208225).

The reviewer independently fetched the published commit, its complete recursive tree and PR metadata through the read-only GitHub connector. The PR head matched the commit above. Its tree, `5782837acca162c28d9ceb3dbcca5b7570db2684`, exactly matched tested local commit `99872c8ff16966e007555962c1f824e831a4e20e`. All eighteen specifically reviewed file Git blob IDs also matched with zero differences. Evidence: `published-source-verification.json` and `final-source-manifest.json`.

The reviewer exported the frozen local commit before adding reviewer-owned test fixtures. Test evidence therefore applies to the byte-identical published source tree; the local and GitHub commit IDs differ because their commit metadata differ. These are local execution results, not GitHub Actions job results. PR #180 was still a draft at readback, which is not treated as assignment completion or approval by the original owners.

This approval covers the reviewed **isolated engineering serving and authorization changes**: the Go mTLS entrypoint, same-origin operator application, restricted PostgreSQL roles and operational functions, transactional certificate authorization, result/lease failure handling, and Linux bounded file opening. It does not approve production deployment or certify a complete EDR product.

**Release and deployment remain NO-GO.** Actual exact-head GitHub execution, the required Windows and Ubuntu deployment-host records, original owner reviews, independent QA's complete acceptance verdict, organization-signed packages, installed-service/database rollback, and named deployment authorization are separate gates. Missing evidence is not a pass.

## Reviewed trust boundaries

The Go `cmd/edrd` source requires separate endpoint and operator client trust roots, verified client certificates, enrolled leaf fingerprints, current tenant/principal status and the operator's current role. The new service uses TLS 1.3 and dedicated loopback listeners. Database startup checks require the actual serving schema, the restricted role groups and exact operational function permissions. Configuration and credentials are read through bounded, regular-file checks with restrictive permission requirements and generic error messages.

The PostgreSQL bootstrap gives the registry login readonly identity access, gives the runtime the explicit operational interfaces, and puts elevated operational functions under a nonlogin function owner with a fixed search path. Administrative enrollment, rotation and revocation functions are not runtime interfaces. The runtime cannot directly write EDR tables or read lease secrets. This is a boundary against database credential privilege escalation; it is not database enforcement of the caller's tenant against a fully compromised backend process that possesses the shared runtime credential.

For writes, the application buffers a bounded request body before beginning the transaction, obtains authorization using the actual verified leaf fingerprint, holds identity/certificate locks through the mutation, and dispatches operations through that same `*sql.Tx`. The transaction has a bounded context. Response status, headers and body remain buffered until commit succeeds. A handler failure, response overflow, panic or commit failure must not release a successful response or lease token.

The operator application rechecks authorization on requests, binds API tenant scope to the authenticated principal, rejects cross-origin browser writes and serves the built React application without introducing a JavaScript bearer credential. Its source distinguishes absent or unknown evidence from a protection verdict.

Linux authenticated file scans now use the existing handle-relative `openat2` opener beneath the policy root and compare opened-file identity with the checked file. The configured root and its ancestors still require administrator control. Windows reparse-safe opening, ACL acceptance and native service behavior remain unproven release gates.

## Findings and disposition

| Finding | Observed defect or gap | Disposition and evidence |
|---|---|---|
| Certificate revocation race | The initial HTTP fingerprint lookup and later database mutation were separate operations; revocation could commit between them. | Fixed by explicit same-transaction agent/operator authorization functions and locks retained through mutation/commit. Independently executed the restricted-role authorization suite and all seven coordinated schedules. |
| Leaf expiry during authorization | A TLS leaf valid at the initial guard could expire while the body was read or a SQL authorization lock was pending. The old wrapper still dispatched and committed the mutation. | Fixed by checking actual peer-leaf validity again after SQL authorization returns. The independent regression failed before the fix and passed after it. |
| Expired lease after a lock wait | Lease SQL used the transaction's start timestamp. A result submitted through a transaction that waited for authorization could be accepted after the actual lease expired. | Reproduced on actual PostgreSQL with an observed lock wait and restricted runtime login. Patched functions lock the matching job, then sample current time. The identical reproduction changed from an accepted, persisted result to rejection with zero results. The frozen-source reproduction also passed. Migration 0013 provides the existing-schema upgrade. |
| Authenticated Linux scan opening | The authenticated scan path did not initially reuse the stronger handle-relative opener used elsewhere in the same Rust agent. | Source now reuses `openat2` and compares file metadata. This source review does not count as a native deployment-host race/ACL acceptance test. |
| Package source identification | An archive manifest could name a SHA while the Go binary's version metadata still reported an uncommitted build. | Packager source now embeds the candidate SHA in the Go and Rust builds. Actual release signing and native installation remain separate. |

The lease fix reaches existing databases through migration 0013. It replaces the five affected function bodies atomically and checks preservation of OID, owner, ACL, security mode and complete function-local configuration. It publishes the version-1 capability only after those checks succeed; bootstrap requires that marker and grants serving roles SELECT only. The Go startup path checks the marker on both database handles before listening. The independent QA agent separately confirmed double application after an obsolete-clock fixture, restricted-role timing tests and old-schema startup rejection on the frozen local candidate. That execution is attributed to QA below.

## Independently executed evidence

### Go transaction failure and expiry tests

The reviewer first copied backend source into an isolated review directory and added independent database/sql driver fixtures, then repeated those tests against an export of frozen commit `99872c8ff16966e007555962c1f824e831a4e20e`. The exported committed files were unchanged; only reviewer-owned test fixtures were added. These are fault-injection tests of the application transaction wrapper, not claims of a real TLS handshake or actual PostgreSQL execution.

Command:

```sh
go test -race -count=1 -v ./internal/edr \
  -run '^TestIndependent(CertificateTransaction|TLSLeafExpiry)'
```

Observed: **PASS**. Coverage included success withheld until commit, commit failure withholding the lease token, denied/error authorization preventing mutation, handler-error rollback, response overflow, oversized body rejected before BEGIN, panic rollback, and actual leaf expiration during authorization.

Evidence:

- `final-transaction-review.log` — frozen-source execution, PASS
- `transaction-review-fixed.log` — earlier fix verification
- `leaf-expiry-before-fix.log`
- `backend/internal/edr/independent_certificate_transaction_test.go`
- `backend/internal/edr/independent_certificate_expiry_test.go`

Reviewed wrapper SHA-256: `68915f8f01892aea7766527c20e24c19bc0ae7bc701a07a61cc6b6df261f85d8`.

### Earlier independently executed PostgreSQL authorization baseline

The reviewer independently ran the copied privilege/bootstrap suite on a fresh PostgreSQL 16.16 cluster before the later capability-marker addition. Runtime and registry tests used actual separate restricted connections authenticated with SCRAM-SHA-256, not only role switching inside an administrator connection. This subsection identifies that earlier tested bootstrap explicitly and is not presented as the final marker-aware privilege suite.

Observed: **PASS** for bootstrap/reapplication, the eleven-function allowlist and security metadata, nested lifecycle writes, **32 denied runtime operations**, **14 denied registry operations**, and seven coordinated certificate revocation/rotation/operator-role/expiry schedules. The concurrency tests required an observed PostgreSQL lock wait and explicit release; they did not infer contention from a scheduled process.

Evidence:

- `postgres-authorization-review.log`
- `sql-snapshot.json`

Reviewed bootstrap SHA-256: `e099d8f814d0caf78b6373ef3060954e6ca55983b08f078ad5a498049065a2e6`.

### Actual expired-lease reproduction

The reviewer started a fresh PostgreSQL cluster and applied the candidate migrations and runtime bootstrap. An administrative transaction held an unchanged certificate row locked. The restricted runtime began its authorization transaction before lease expiry and was observed waiting on that lock. The test verified actual lease expiry before releasing the lock, then submitted a synthetic result through the operational function.

| Observation | Before fix | After patched migration bodies |
|---|---:|---:|
| Actual authorization lock wait observed | Yes | Yes |
| Lease expired before authorization was released | Yes | Yes |
| Certificate authorization allowed | Yes | Yes |
| Expired result accepted | **Yes** | **No** |
| Persisted result rows | **1** | **0** |

Evidence:

- `lease-expiry-repro.sh`
- `lease-expiry-before-fix.log`
- `lease-expiry-after-fix.log`
- `final-lease-expiry-review.log` — frozen commit, migrations 0001–0013, bootstrap, actual observed lock wait, rejected result, zero persisted rows and unchanged leased state; PASS

### Separately attributed independent QA execution

The independent QA agent executed the final marker-aware privilege suite and reviewer-owned startup regressions on a clean clone of frozen local commit `99872c8ff16966e007555962c1f824e831a4e20e`. QA reported exit 0 for the exact eleven-function catalog checks, **35 denied runtime operations**, **17 denied registry operations**, 0013 double-upgrade metadata preservation, all **seven certificate-authorization schedules** and **eight lease-timing cases**. QA's six startup regressions also passed, including old function bodies without the capability marker and an incompatible marker version.

Evidence supplied by QA: `qa-work/prepublication-privilege-recheck.log`; the final QA ledger remains a separate deliverable. These results are not relabeled as this reviewer's own execution.

The final reviewed hashes are recorded in `final-source-manifest.json`, including:

- Migration 0013: `3268d2b9721c7a3cc805688c8f284202ca81cdceb52e477b965633e4aaf84534`.
- Marker-aware runtime bootstrap: `3e58c07c30cf17f7961eaf64b52393c57553ed2e95ed7b3d6695c844932ce3d0`.
- Transaction wrapper: `68915f8f01892aea7766527c20e24c19bc0ae7bc701a07a61cc6b6df261f85d8`.

These are synthetic protocol fixtures. They do not demonstrate an antivirus detection, EICAR scanning, authenticated telemetry provenance or native host protection.

## Original requirements and remaining approval boundaries

Issue #1 requires delivery and review of security trust, detection and privacy requirements. The original owner's latest reviewed comment withholds security signoff pending actual TLS serving, persisted revocation evidence, exact-head CI and independent QA: <https://github.com/suhaylx/EDR/issues/1#issuecomment-7067873522>. This independent review must not be presented as that owner's approval.

The current source and installation manual honestly limit the implementation. Legacy lab telemetry and synthetic Event 7 fixtures are not authenticated native Sysmon delivery. A real Event 7 load must retain its genuine provider/channel/record identity and correlate with the appropriate tenant, device, boot and process evidence; FileCreate is not proof of a DLL load. Missing source coverage or scanner state remains unknown/degraded, not healthy.

The engineering candidate does not establish full quick/full scan profiles, signed policy/command delivery with all anti-replay requirements, quarantine/restore, tamper protection, native tray/privileged IPC integration or deployment-host service acceptance. A ClamAV PONG only proves daemon liveness; an engine fixture outside the actual Rust-to-daemon-to-backend-to-SOC host path does not establish integrated acceptance or full signature-database health.

Actual Windows and Ubuntu deployment-host tests are still blocked by reachability. Browser accessibility execution and one Rust Unix-socket test have environment restrictions. Container tests do not waive them. Ephemeral signing-key tests are not organizational release signatures, and POSIX file-switch fixtures are not installed-service or database rollback rehearsals.

## Final attribution checklist

All source-review attribution steps are complete:

1. Complete: independently verify immutable GitHub commit `fb0891f98919fd0a166ff10427088f195d208225`, PR #180 head, identical full source tree and eighteen reviewed blob IDs.
2. Complete: compare reviewed security files with the frozen local committed tree and record their hashes in `final-source-manifest.json`.
3. Complete: review the versioned timing upgrade, independently repeat the expired-lease reproduction on the frozen source, and obtain separately attributed QA upgrade/privilege execution.
4. Complete: run the focused independent Go regressions on the frozen backend source.
5. Complete: **APPROVE the reviewed changes for isolated engineering evaluation at the exact published SHA. Release/deployment remains NO-GO; original Agent 1 approval remains outstanding.**

### Exact reviewed source links

- [Go startup and schema capability checks](https://github.com/suhaylx/EDR/blob/fb0891f98919fd0a166ff10427088f195d208225/backend/cmd/edrd/main.go)
- [Transactional certificate authorization and commit-before-response handling](https://github.com/suhaylx/EDR/blob/fb0891f98919fd0a166ff10427088f195d208225/backend/internal/edr/certificate_transaction.go)
- [Restricted runtime database privileges](https://github.com/suhaylx/EDR/blob/fb0891f98919fd0a166ff10427088f195d208225/backend/bootstrap/runtime_privileges.sql)
- [Versioned lease-clock upgrade](https://github.com/suhaylx/EDR/blob/fb0891f98919fd0a166ff10427088f195d208225/backend/migrations/0013_scan_lease_wallclock.up.sql)
- [Linux authenticated scan-file handling](https://github.com/suhaylx/EDR/blob/fb0891f98919fd0a166ff10427088f195d208225/agent/src/scan_file.rs)
- [Installation and approval boundaries](https://github.com/suhaylx/EDR/blob/fb0891f98919fd0a166ff10427088f195d208225/docs/INSTALLATION.md)
