# TuranSec EDR — Days 4–6 accelerated sprint and release decision

**21 November 2026, Asia/Tashkent.** Day 4/5/6 are three execution phases on the same calendar date, NOT three elapsed calendar days. Source is draft [PR #165](https://github.com/suhaylx/EDR/pull/165), based on [PR #143](https://github.com/suhaylx/EDR/pull/143). Nothing was merged to main or deployed to Windows/Ubuntu servers.

## Day 4 — backend source integrity

- Go Ingest now rejects event image and file path fields longer than **1024 bytes** (was 32768), consistent with the strict React telemetry display contract. It also denies unsafe control characters in event type/source/image/file path/detail.
- New day4_event_display_contract_test.go contains positive and negative 1024/1025 and 4096/4097 boundary fixtures, control-character denials and store-unchanged checks for rejected events.
- The shared-token Go API still stores events in memory and is NOT a tenant- and certificate-authenticated production service.

## Day 5 — detection and SOC evidence honesty

- Agent 1 process/network correlation now requires two observed Sysmon records: EID1 process creation and EID3 connection with the same reported device, ProcessGuid, **nonempty matching BootID**, and a forward time window no longer than ten minutes. Missing boot identity now refuses correlation.
- Expanded agent1_behavior_test.go positive and negative cases for missing/equal/different boot, cross-device, unrelated process, time reversals and legitimate system binaries.
- React telemetry/coverage now highlights large gaps between sender-reported source time and server receipt as possible **queue latency, clock drift or sender error**, not malware proof. Negative tests cover missing and server-received times.

## Day 6 — Windows boot scope and laboratory QA

- Windows Rust Sysmon collector derives a sender-reported current-boot marker from local Win32_OperatingSystem.LastBootUpTime when CIM is available. It attaches that marker only to events dated inside **the current OS boot**. Old log entries do not inherit today's boot ID; missing CIM leaves BootID absent.
- Rust fixtures test honest marker/no marker behavior and bad marker rejection. This source remains **unattested** and only usable through a Windows-local SSH tunnel with the shared development token.
- Updated Windows quickstart covers configured Sysmon Event IDs 1–29 and 255, ascending RecordID pages (up to 256/poll), privacy, possible backlog and dropped events. No statement claims all 30 event classes are always enabled.
- Added scripts/run-day6-local-qa.sh to run Go/race/vet, Rust Linux tests, React Node/TS/build, real compiled Go HTTP loopback smoke and SHA256 on an authorized non-root Ubuntu development host. It is not an endpoint deployment tool and was not run here.

## GitHub Actions blocker and acceptance

At initial checks, PR #143 and PR #165 workflows concluded FAILURE with **no job execution steps and empty runner names**. This is a GitHub Actions startup/availability problem to investigate; available evidence does NOT identify a failing source command. Earlier green CI on other PRs cannot be reused for this exact candidate. Check GitHub Actions permissions, billing/usage, runner availability and job annotations. Restore execution then rerun exact final PR #165 head.

| Gate | Latest disposition |
| --- | --- |
| Backend Go unit/race/vet and new evidence tests | CODE COMMITTED — exact-head CI FAILED BEFORE STEPS |
| Native Windows and Ubuntu Rust agent tests/build | CODE COMMITTED — exact-head CI FAILED BEFORE STEPS |
| React TS/Node/source-receipt tests + responsive UX | CODE COMMITTED — exact-head CI FAILED BEFORE STEPS |
| Locally runnable Day 6 QA script and compiled Go smoke | CODE COMMITTED — NOT RUN |
| Real Windows Sysmon, Linux sensor and ClamAV/EICAR-only | HOST NOT RUN |
| Certificate-bound tenant/device mTLS, event persistence, replay/recovery | NOT END-TO-END INTEGRATED |
| Reproducible dependency locks, signed agents, signed updates | BLOCKED |
| Independent QA + InfoSec release approval | **NO GO** |

## Owners and immediate tasks

- **InfoSec Agent 1:** Review sender boot markers, correlation provenance, time-skew and replay cases. Add independent negative fixtures.
- **Backend Agent 2:** Reconcile newer mTLS/tenant and PostgreSQL branches with this lab candidate; no blind whole-file overwrite. Verify with actual Go/Rust/SQL execution.
- **QA Agent 3:** Investigate exact GitHub workflow zero-step failure with repository administrator. Once runnable, test latest SHA and coordinate real Windows/Linux/ClamAV acceptance in authorized isolated lab. Never label tests PASS without output.
- **Frontend Agent 5:** Review React and Go-served UI, large time-gap warning, keyboard/mobile/error states, safe token origins and source evidence provenance.
- **PM Agent 4:** Maintain exact SHA, per-gate PASS/FAIL/NOT RUN, owners and rollback; no main merge or server changes without user approval.

**Sprint result:** Days 4–6 development changes pushed for review. Real laboratory release approval is pending. Production EDR remains **NO GO**.
