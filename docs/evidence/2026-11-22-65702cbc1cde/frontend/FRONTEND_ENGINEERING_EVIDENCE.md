# Frontend engineering evidence

Exact source: `65702cbc1cde6750304d9e438bb27bc0537c2d45`. Tree: `072fcd9d483aee90addddc9801f56b754285516d`.

- [Successful job 136989003202](https://github.com/suhaylx/EDR/actions/runs/44951109428/job/136989003202), run 44951109428 attempt 1.
- [Artifact 14725995535](https://github.com/suhaylx/EDR/actions/runs/44951109428/artifacts/14725995535).
- ZIP SHA-256: `f7873843eea6aedacb9ce75fc420db3a62dd246027076b27a55c98d1ab13e95c`.
- Raw browser-report SHA-256 independently checked before workspace loss: `4e80acc55c18df8852a8a7985b2db0b1b91de35003ed541c86280fa39956dfa6`.

Locked dependencies, TypeScript, production build and all 374 unit tests passed. All 14 actual Chromium 159.0.8154.6 browser scenarios passed, with no browser errors. These exercised the original SOC and companion, mTLS rejection, authentication clearing, permission gates, stale refresh cancellation, scheduling/cancellation, alert/case workflows, keyboard interactions, mobile geometry and uncertain mutation outcomes.

Interrupted acknowledgement produced exactly one server POST and one browser POST. The server committed, response headers were truncated, and the UI displayed an explicit unknown outcome without automatic retry. Reconnect loaded committed state without another POST. Mobile viewport/document/body widths were all 390 px, with no outside-viewport elements. Original companion evidence included all six read-only sources, tabs and authentication-loss clearing.

All 15 axe scans report zero violations. The original companion and all three added desktop workflow scans have zero incomplete findings. In total 12 scans are complete; the three retained mobile table scans have 32, 22 and 32 incomplete contrast measurements because content is clipped inside scroll regions. These 86 records remain needs-review. This is automated frontend engineering verification using the built React app and synthetic API fixtures with ephemeral mTLS; actual Go/PostgreSQL integration is covered by its separate job. It does not grant native-host acceptance, manual accessibility certification, InfoSec approval or deployment authorization.

This summary records the frontend reviewer's verified findings and artifact hashes; it is not presented as a byte-identical copy of the earlier scratch report.
