# TuranSec EDR — accelerated three-day sprint execution and release gate

**Owner request:** run three sprint phases immediately, without merging to main or touching the rebuilt lab servers. **Date:** 21 November 2026, Asia/Tashkent. **Branch:** integration/day3-evidence-gates-20261121; [draft PR #143](https://github.com/suhaylx/EDR/pull/143). "Day 1/2/3" below are *execution phases in one session*, not three elapsed calendar days.

## Phase 1 — integration and source-evidence checks

Committed to PR #143:
- QA M51–100 synthetic negative tests, PostgreSQL concurrency/restart fixtures and Go race CI inherited from QA PR #137 and its parent PRs #132 and #96.
- Strict Rust/Go/React Sysmon provider/channel consistency guards from separately green security PR #133. The fields are **sender-reported, not cryptographically attested**.
- Independent EID7 true DLL load versus EID11 file-create provenance regression tests from separately green QA PR #134. Never turn file creation into execution proof.

## Phase 2 — harden and package

Committed to PR #143:
- P0 lab listener guard and 25 negative bind checks from PR #119. Shared-token development Go API now rejects wildcard/public/DNS binds; use EDR_ADDR=127.0.0.1:8080 behind an administrator SSH tunnel.
- New scripts/smoke-ubuntu-lab-api.sh, integrated into Ubuntu Go backend artifact workflow. It starts a **compiled Go binary**, verifies real local HTTP health and missing/wrong bearer denial, checks a **synthetic** Sysmon DNS event with source ID/RecordID/provider and server receipt, verifies no DNS-only detection, rejects fake source provider, type mismatch and clipboard content, verifies rejected data does not persist, checks served SOC UI and denies public API binding.
- React SOC artifact workflow now stages SHA256SUMS.txt and LAB_ONLY.txt and verifies its generated checksum before upload. Other OS build workflows already include checksums.

**Reproducibility gap:** frontend/package-lock.json and agent/Cargo.lock are absent in this branch. Unsigned, dynamically resolved dependency artifacts cannot be represented as enterprise-trusted releases.

## Phase 3 — test evidence and lab release decision

### GitHub Actions startup blocker (not an observed code-test failure)

At the start of this work:
- [QA PR #137](https://github.com/suhaylx/EDR/pull/137) finished 3/3 CI workflows SUCCESS.
- [Security PR #133](https://github.com/suhaylx/EDR/pull/133) finished 5/5 CI workflows SUCCESS.
- [QA PR #134](https://github.com/suhaylx/EDR/pull/134) finished 3/3 CI workflows SUCCESS.

These are older, separate SHAs. The combined PR #143 **has not passed**.

For the first PR #143 head, GitHub Actions returned 5/5 workflows FAILURE **before any job recorded an execution step**:
- [Starter 44933887576](https://github.com/suhaylx/EDR/actions/runs/44933887576): Go/Rust/UI jobs failed without steps.
- [Frontend 44933887563](https://github.com/suhaylx/EDR/actions/runs/44933887563): both jobs failed without steps.
- [Ubuntu Rust 44933887550](https://github.com/suhaylx/EDR/actions/runs/44933887550): no job steps.
- [Windows Rust 44933887567](https://github.com/suhaylx/EDR/actions/runs/44933887567): no job steps.
- [Ubuntu Go 44933887658](https://github.com/suhaylx/EDR/actions/runs/44933887658): no job steps.

The root cause is **not established**. A similar pre-step failure is present on the separately stacked BE-131–135 backend PR #139. Inspect the GitHub repository Actions UI, job annotations, runner availability, account Actions billing/quotas and organization settings. Avoid guessing that Go/Rust tests failed. Restore runnable CI, then rerun the exact **latest** PR #143 SHA and record each actual job outcome.

### Release gate matrix

| Gate | Required evidence | Status |
| --- | --- | --- |
| Go backend | go test ./..., race and vet on exact combined head | BLOCKED — runner/startup failure |
| Compiled Go API | New scripts/smoke-ubuntu-lab-api.sh against the freshly built binary | COMMITTED; NOT RUN |
| Windows Server 2022 Rust | Native cargo tests, build, CLI negative smoke, SHA256 | BLOCKED — runner/startup; unsigned |
| Ubuntu 24.04 Rust | Native cargo tests, build, CLI smoke, SHA256 | BLOCKED — runner/startup; unsigned |
| React UI | Strict TypeScript, Node tests, Vite build, no-public-HTTP login and SHA256 | BLOCKED — runner/startup |
| PostgreSQL | Disposable DB migrations, concurrency/revocation/replay/restart | BLOCKED — runner/startup |
| Actual Windows | Signed Sysmon, real enabled EIDs/RecordIDs, heartbeat, missing-event accounting | HOST NOT RUN |
| Actual Linux | Readable procfs snapshots, permissions, restart and resource limits | HOST NOT RUN |
| Actual ClamAV | Real clamd, DB trust/version, benign plus official EICAR-only, timeout and offline cases | HOST NOT RUN |
| Device authentication | Certificate- and tenant-bound identity across all live endpoint APIs | NOT INTEGRATED in shared-token Go lab API |
| Durability | Durable event storage, dedup, offline replay, retention and restoration | NOT INTEGRATED end-to-end |
| Production release | Signed agents and update, safe response, tenant isolation, independent red-team signoff | NO GO |

## Interface and scope boundaries

The Go SOC backend here is **in-memory lab-only**, even though separate PostgreSQL enrollment/scan modules exist. The advanced SOC backend stack [PR #139](https://github.com/suhaylx/EDR/pull/139) is divergent and is **not imported** in PR #143; it requires compatibility review and CI restoration first. A reported Sysmon Event ID is not device attestation. Linux /proc inventory is not process-creation telemetry. A scanner error is not a clean verdict. No automated remediation or customer deployment is authorized.

## Roles — required exact-head evidence

| Owner | Workstream / next deliverable | Acceptance |
| --- | --- | --- |
| Agent 1 — InfoSec | Review spoofable provider claims, lab token boundaries, real scan file/verdict trust | Diff-backed negative tests, scoped PR and security signoff |
| Agent 2 — Backend | Determine PR #139 Actions startup cause; reconcile active mTLS/scan/heartbeat with integrated safety guards | CI job execution plus authenticated Go/Rust/SQL evidence; no blind branch overwrite |
| Agent 3 — QA | Re-run PR #143 exact-head unit/race/DB, run compiled-binary smoke, organize real Windows/Linux/ClamAV host tests | PASS/FAIL/NOT RUN per test and independent signed-off record |
| Agent 5 — Frontend | Verify both dashboards' source ID/RecordID, timestamps, unknown coverage, accessibility and no-public-HTTP token entry | Node tests, browser keyboard/empty/error state evidence |
| Agent 4 — PM | Track exact head SHA, runner incident, responsible role, packaging and rollback | Report blockers and refuse premature main merge or release |

## Operator handoff after CI is restored

1. Review [PR #143 checks](https://github.com/suhaylx/EDR/pull/143/checks). Download only from a successful run at the **final candidate SHA**, then verify SHA256SUMS.txt in every agent/backend/UI artifact.
2. Follow docs/LAB_RELEASE_CANDIDATE_DAY3.md and the Windows/Linux telemetry quickstarts on isolated authorized, freshly rebuilt VMs. Use backend loopback and endpoint-local SSH forwarding; never expose TCP 8080.
3. Capture sanitized health, genuine process/event RecordIDs, current ClamAV EICAR-only results, backend logs and SOC screenshot timestamps. Distinguish synthetic CI from actual endpoint behavior.
4. On mismatch, stop portable agents, close tunnels and restore previous web binary/assets. No destructive cleanup or quarantine.
5. Even after CI and host evidence, the maximum claim is **isolated lab evaluation candidate**. Production is **NO GO** until per-device mTLS identity, durable evidence, signed agents/updates and independent QA/InfoSec acceptance.

**Milestone accounting:** These phases were executed immediately in one session; they are not three days elapsed or proof of enterprise EDR completion.
