# TuranSec EDR candidate evidence — 22 November 2026

**The integrated engineering candidate runs and passes the core local integration checks. Release and deployment remain NO-GO.** This evidence does not declare all four original sprint assignments complete.

Candidate: [PR #180](https://github.com/suhaylx/EDR/pull/180), commit [`fb0891f98919fd0a166ff10427088f195d208225`](https://github.com/suhaylx/EDR/commit/fb0891f98919fd0a166ff10427088f195d208225). Source tree: `5782837acca162c28d9ceb3dbcca5b7570db2684`.

The source commit stays fixed. This separate evidence commit adds records about that candidate; its own SHA is not a replacement candidate SHA. The primary local ledgers verify the canonical candidate commit and a clean checkout before and after execution. Reviewer records distinguish tests on the identical prepublication tree from tests on the canonical commit. None of the local results are relabelled as GitHub Actions results.

## Actual verification

| Gate | Observation | Evidence |
|---|---|---|
| Go | Build, tests, race tests and vet all passed at the published SHA | [ledger](local/backend-linux.json), [output](local/backend-linux.log) |
| PostgreSQL 16 | Full migration/enrollment/rotation/revocation/queue/results/SQL suite passed; 35 runtime and 17 registry forbidden operations denied; 7 authorization and 8 lease timing schedules passed | [ledger](local/postgres-linux.json), [output](local/postgres-linux.log) |
| Database restart | Actual PostgreSQL stop/start observed; consumed challenge and queue persistence verified afterward | [seed](local/postgres-seed-linux.json), [verification](local/postgres-verify-linux.json), [before](local/postgres-start-before.txt), [after](local/postgres-start-after.txt) |
| Integrated candidate | 10 checks passed using compiled Go, PostgreSQL, the actual Rust client and built React assets | [checks and limits](local/integrated-candidate.json), [command ledger](local/integration-linux.json), [output](local/integration-linux.log) |
| React | 326 tests passed, zero failed; typecheck and build passed. Full frontend gate remains failed because browser dependencies could not install | [ledger](local/frontend-linux.json), [output](local/frontend-linux.log) |
| Browser | An installed Chromium fallback was attempted; socket creation failed with EPERM before any browser case executed | [native browser attempt](final-browser-native.log) |
| Rust | Build passed; 59 tests passed and 1 genuine Unix-socket test failed with EPERM. Zero tests ignored; native Windows execution is missing | [ledger](local/rust-linux.json), [output](local/rust-linux.log) |
| Release/collector tools | 12 cryptographic-tamper/filesystem-rollback and 8 host-evidence collector regressions passed | [ledger](local/release-tools-linux.json), [output](local/release-tools-linux.log) |
| GitHub exact-head CI | Run 44943696845 failed: all 8 jobs had runner_id=0 and zero executed steps. Runner/account root cause remains unconfirmed | [GitHub run](https://github.com/suhaylx/EDR/actions/runs/44943696845), [record](github-exact-head.json) |

The integration proves authenticated transport and storage, tenant/origin/TLS denials, persisted revocation on reused TLS connections, a real Rust heartbeat and claim/renew/error-result lifecycle, and serving the React assets. Its malicious result is synthetic; absent ClamAV is reported as an error. It does not establish real integrated antivirus detection, native host protection or browser accessibility.

## Independent reviews

- [Independent InfoSec review](infosec/INDEPENDENT_INFOSEC_REVIEW.md): **APPROVE for the reviewed isolated engineering scope; release NO-GO.** The reviewer verified 18 published source blobs, ran nine transaction/failure/expiry behaviors under the race detector and independently reproduced expired-lease rejection on real PostgreSQL. [Source readback](infosec/published-source-verification.json), [transaction execution](infosec/final-transaction-review.log), [lease execution](infosec/final-lease-expiry-review.log).
- [Independent QA review](qa/FINAL_QA_REVIEW.md): **Scoped engineering APPROVE; full acceptance NOT APPROVED; release NO-GO.** QA independently executed the SQL privilege/timing/upgrade tests, six startup and two display regressions, backend checks and tool regressions. [Machine-readable verdict and attribution](qa/FINAL_QA_VERDICT.json).

These fresh reviewers are separate from the implementers. Their reports do not substitute for the original Agent 1 or Agent 3 owner approval in issues #1 and #3. A draft PR and scheduled automation are not completion evidence.

## Host and scanner observations

[Host execution summary](host/host-execution-summary.json) and [reachability record](host/remote-reachability.json): the authorized Ubuntu and Windows lab endpoints were unreachable. No authenticated host session was established. Native Windows service/Sysmon/ACL and Ubuntu deployment-host acceptance remain unexecuted.

The host specialist executed the official ClamAV 1.5.5 scanner in the isolated Debian environment after verifying the package publisher signature and the available daily/bytecode database signatures. A benign fixture returned exit 0 and the harmless EICAR fixture returned exit 1. The required main database was unavailable after vendor 429/cooldown, so full signature health remains incomplete. This scanner observation is explicitly not attributed to the EDR candidate or the deployment hosts. [Detailed observations](host/scanner-container-observations-final.json), [benign output](host/clamscan-benign.log), [EICAR output](host/clamscan-eicar.log).

## Package and installation manual

An explicitly **unsigned Linux x86_64 portable engineering archive** was built from the canonical commit. Both Go and Rust binary version strings contain the full candidate SHA. All 28 packaged files match their manifest hashes, and the package/manual database paths agree. [Package validation](package-validation.json), [build output](final-package-build.log).

Archive SHA-256: `2de710826b3f45861ed36da2fca359835c5c73201000cd715374b1e2e94cd510`. It is not a signed installer or an installed-service acceptance result. Approved organizational signing credentials/service were not available; no substitute identity was created.

The [updated installation, upgrade and rollback manual](https://github.com/suhaylx/EDR/blob/fb0891f98919fd0a166ff10427088f195d208225/docs/INSTALLATION.md) documents restricted PostgreSQL identities, separate PKI, startup, Rust operations, the SOC, migration 0013, package verification and the remaining acceptance gates. Migration 0013 replaces obsolete lease timing functions atomically, preserves their security metadata and publishes a mandatory read-only capability marker. It does not authorize a deployment.

## What remains before deployment authorization

1. Restore GitHub runner allocation through repository/account administration or an approved isolated runner, then execute and pass the exact-head jobs. [Runner blocker #153](https://github.com/suhaylx/EDR/issues/153). No billing or account-policy changes were made.
2. Execute the blocked Rust/browser checks and actual Windows/Ubuntu acceptance on authorized accessible hosts, including genuine EICAR/Sysmon evidence through the integrated path.
3. Obtain explicit original InfoSec and QA owner verdicts on this candidate and complete the original sprint acceptance criteria.
4. Produce approved publisher-signed packages, including native Windows Authenticode/service evidence, and rehearse installed-service plus database rollback on the approved hosts.
5. Obtain the named deployment owner's authorization for exact signed hashes, targets, canary, window and tested rollback.

No merge or deployment was performed. The existing hourly four-agent completion monitor remains enabled; the completion condition is not met. No production-readiness claim is made.
