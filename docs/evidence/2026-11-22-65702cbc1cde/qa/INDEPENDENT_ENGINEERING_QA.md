# Independent engineering QA verdict

Source: `65702cbc1cde6750304d9e438bb27bc0537c2d45`. Candidate run: [44951109428, attempt 1](https://github.com/suhaylx/EDR/actions/runs/44951109428/attempts/1).

## Verdict

**APPROVE within the exercised engineering scope. Full installed-system acceptance NOT APPROVED. Release/deployment NO-GO.**

The independent QA reviewer separately examined all eight actual job logs, verified all seven artifact SHA-256 digests, and checked all nine command ledgers against the candidate SHA, run URL and attempt. Every recorded command exited 0. The frontend artifact download was reused but its bytes and raw reports were independently verified.

This durable record transcribes the reviewer's verified findings after the execution workspace became unavailable. It is not a byte-identical copy of the earlier scratch report and does not claim that file's hash. It is an independent engineering review, not a formal GitHub approval or the original Agent 3 sprint-owner verdict.

| Gate | Verified result | Job |
|---|---|---|
| Go | Build, normal tests, race tests and vet PASS | [136989003080](https://github.com/suhaylx/EDR/actions/runs/44951109428/job/136989003080) |
| Linux Rust | Locked build/test/check; 60 passed, 0 failed, 0 ignored | [136989003149](https://github.com/suhaylx/EDR/actions/runs/44951109428/job/136989003149) |
| Windows Rust | Locked build/test/check; 48 passed, 0 failed, 0 ignored; collector PowerShell syntax PASS | [136989003093](https://github.com/suhaylx/EDR/actions/runs/44951109428/job/136989003093) |
| Release tools | 64 fixture tests PASS: 12 signature/rollback, 8 host-collector, 8 release-record, 36 installer | [136989002870](https://github.com/suhaylx/EDR/actions/runs/44951109428/job/136989002870) |
| PostgreSQL 16 | Full SQL/security/concurrency/upgrade suite and actual restart/persistence PASS | [136989003166](https://github.com/suhaylx/EDR/actions/runs/44951109428/job/136989003166) |
| Integrated candidate | Five successful command records; real Go/PostgreSQL/Rust/React-assets harness 10/10 PASS | [136989003115](https://github.com/suhaylx/EDR/actions/runs/44951109428/job/136989003115) |
| Frontend | Typecheck/build; 374 unit tests; 14 real Chromium scenarios PASS | [136989003202](https://github.com/suhaylx/EDR/actions/runs/44951109428/job/136989003202) |
| Required aggregate | All required component jobs succeeded | [136989699428](https://github.com/suhaylx/EDR/actions/runs/44951109428/job/136989699428) |

## PostgreSQL evidence

The suite exercised 35 runtime denials, 17 registry denials, migration 0013 double-upgrade, seven certificate schedules and eight lease schedules. The recorded PostgreSQL service start time changed from `2026-11-21T21:21:40.828877+00:00` to `2026-11-21T21:22:49.852606+00:00`; subsequent challenge/queue persistence verification passed.

## Browser and accessibility evidence

The interrupted acknowledgement trace contains one server POST and one browser POST, committed acknowledgement state, `ERR_RESPONSE_HEADERS_TRUNCATED`, and the explicit unknown-outcome UI. No-retry and reconnect assertions passed. All original companion scenarios completed, including six read-only routes, tab behavior and clearing after authentication loss.

Fifteen axe scans report zero violations. Twelve have zero incomplete findings, including all three unclipped desktop workflow states and the original companion. Three mobile scans preserve 32/22/32 partially obscured contrast measurements inside horizontal table-scroll regions. They remain needs-review; complete desktop measurements do not retrospectively convert incomplete mobile measurements to passes. No full WCAG, screen-reader, mobile-navigation or manual accessibility certification is granted.

## Remaining release gates

Actual designated Windows/Linux installation and acceptance, managed ClamAV/Sysmon host evidence, fresh InfoSec and original role-owner verdicts, trusted publisher signatures, live installed-service/database rollback and deployment authorization remain outstanding. The previous InfoSec audit stopped at an automatic security filter and was not treated as an approval. Package fixture tests and native GitHub compilation are not substitutes for those gates.
