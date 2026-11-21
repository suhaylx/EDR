# TuranSec EDR: verified engineering candidate

Recorded 22 November 2026 (Asia/Samarkand).

**Exact source:** [`65702cbc1cde6750304d9e438bb27bc0537c2d45`](https://github.com/suhaylx/EDR/commit/65702cbc1cde6750304d9e438bb27bc0537c2d45) in [PR #180](https://github.com/suhaylx/EDR/pull/180).

**Engineering CI: PASS. Independent engineering QA: APPROVE within scope. Full assignment completion and installed-system acceptance: NOT ESTABLISHED. Release/deployment: NO-GO.**

The GitHub runner blocker is cleared. The [actual candidate run 44951109428, attempt 1](https://github.com/suhaylx/EDR/actions/runs/44951109428/attempts/1) completed successfully on this exact source. All eight required jobs and all fifteen supporting workflows passed. These are executed checks with assigned runners, job logs and artifact digests.

## Evidence

- [Independent engineering QA verdict](qa/INDEPENDENT_ENGINEERING_QA.md)
- [Frontend engineering results and limitations](frontend/FRONTEND_ENGINEERING_EVIDENCE.md)
- [All fifteen supporting workflows](SUPPORTING_CI.md)
- [Exact-source job/step records](exact-head-ci.json)
- [Seven candidate artifact digests and download links](artifact-digests.json)
- [Installation and rollback manual](https://github.com/suhaylx/EDR/blob/65702cbc1cde6750304d9e438bb27bc0537c2d45/docs/INSTALLATION.md)
- [Linux installation/service guide](https://github.com/suhaylx/EDR/blob/65702cbc1cde6750304d9e438bb27bc0537c2d45/docs/LINUX_SERVICE_INSTALLATION.md)

## Executed results

| Component | Verified result |
|---|---|
| Go | Build, tests, race tests and vet passed |
| Native Linux Rust | 60 tests passed; none failed or ignored; build/check passed |
| Native Windows Rust | 48 tests passed; none failed or ignored; build/check passed |
| PostgreSQL 16 | Migrations, restricted roles, negative tests, concurrent schedules and actual restart/persistence passed |
| Go/PostgreSQL/Rust/React-assets integration | 10/10 checks passed |
| React SOC and companion | Typecheck/build, 374 unit tests and 14 real Chromium scenarios passed |
| Accessibility | 15 scans, zero reported violations; 12 complete scans; three mobile table scans retain 86 incomplete contrast measurements |
| Release/installer tooling | 64 fixture tests passed |

The final browser trace proves one submitted acknowledgement POST at the server and browser, explicit unknown outcome after truncated response headers, and successful reconnect without resubmitting. The final original companion scan has zero incomplete findings. Mobile clipping limitations remain recorded and require manual follow-up.

## Package delivery

[Native package run 44956977201](https://github.com/suhaylx/EDR/actions/runs/44956977201) builds unsigned Linux and Windows portable archives from the source above. Its delivery-workflow commit is `c9b8f67347eb03c7df6c647a19dcf6bfde8898c3`, on a separate release-build branch. The workflow checks out the tested source explicitly, verifies package file hashes and native binary source identifiers, and prepares reviewable draft assets. At the creation of this evidence record, package execution is still in progress; this section does not claim successful delivery.

## Remaining release and assignment gates

Original role-owner approvals and a fresh explicit InfoSec verdict remain missing. Required actual authorized Ubuntu and Windows Server 2022 host tests, managed ClamAV/EICAR and Sysmon evidence, Windows service/installer and local IPC implementation/acceptance, approved publisher signatures, live installed-service/database rollback and concrete deployment-owner authorization are not established. Package fixture tests and native GitHub runners do not replace installed-host acceptance.

The original seven-day sprint has a three-day baseline plus four remaining days. This evidence does not mark all four engineering assignments complete. PR #180 remains draft and unmerged; main remains at `554ea9ee7d372b186bd0aa4116224cdd9ba7548e`. No production-readiness or deployment approval is granted.

## Record provenance

The independent QA and frontend agents verified the actual artifacts before the execution workspace became unavailable. This durable evidence set records their verified findings and GitHub metadata; reconstructed prose is identified as such. The linked original Actions artifacts retain the actual command ledgers, reports and screenshots. No private credentials or signing keys are included.
