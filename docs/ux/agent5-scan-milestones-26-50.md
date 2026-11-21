# Agent 5 — Scan Evidence Milestones M26–M50

**Product:** TuranSec EDR, original React/TypeScript SOC laboratory UI.
**Workstream:** UX-001 / scan-history truthfulness. **Status:** source in a dependent
draft PR based on Agent 5 PR #100; not a production scan feature, not
25 independently deployed releases. No change to Rust ClamAV worker or
Go API command authorization.

## Evidence contract

The current Go/Rust lab implements **path** scans; quick and full are
request modes without executed scanner profiles. An untrusted
`completed` + `malicious | suspicious | clean_by_signature` report for
quick/full is an **unsupported scan claim**. A successful verdict with
absent/unrecognized scan mode is **unverified mode**, never evidence
of successful scanning. Path-scan results are reported by a shared
development bearer token and are **not** authenticated scanner
attestations. `clean_by_signature` is not file or endpoint safety.
`queued` and `leased` are not scanner execution. `error` and
`unscanned` remain distinct even when delivery says `completed`.
Real DB age, integrity, device enrollment, tenant scope, request
signatures and response authenticity are not instrumented in this
React view.

The source code in this PR deliberately reconciles and strengthens
pending review fixes from PR #53 (scan-display capability truthfulness)
and PR #54 (capability-aware history filtering) without merging their
branches or changing backend rules. The legacy `scan-history.ts` and
new `scan-evidence.ts` use the same fail-closed interpretation.

## 25 executable acceptance milestones

Each item M26–M50 below has a corresponding named test in
`frontend/tests/scan-25-evidence.test.mjs`. These cases are **only
verified once exact-HEAD GitHub Actions is successful**.

| ID | Analyst-visible acceptance criterion |
| --- | --- |
| M26 | Queued request remains pending, no execution claim |
| M27 | Leased job does not become completed scan |
| M28 | Expired job requires attention, not success |
| M29 | Generic failed job cannot appear clean |
| M30 | Failed + unscanned is distinct from scanner error |
| M31 | Failed + error is danger-classified |
| M32 | Completed delivery + error has no successful scan |
| M33 | Completed delivery + unscanned remains unscanned |
| M34 | Quick + malicious claim is unsupported |
| M35 | Quick + suspicious claim is unsupported |
| M36 | Quick + signature-negative claim is unsupported |
| M37 | Full + malicious claim is unsupported |
| M38 | Full + suspicious claim is unsupported |
| M39 | Full + signature-negative claim is unsupported |
| M40 | Path + malicious reports a non-attested signature claim |
| M41 | Path + signature-negative never claims endpoint safety |
| M42 | Path + suspicious remains an unverified analyst signal |
| M43 | Missing mode + successful verdict is unverifiable |
| M44 | Unknown and case-folded quick/full mode values fail closed |
| M45 | Unknown job state/verdict cannot masquerade as clean |
| M46 | Exact endpoint filtering cannot join other devices by substring |
| M47 | Path/quick/full/unknown scan-mode filtering is functional |
| M48 | Case-insensitive metadata search never mutates API records |
| M49 | Chronological sorting uses timestamps, with missing values last |
| M50 | Summary, 25/50/100 pagination and categories never inflate successes |

## Implemented SOC UI

- `frontend/src/ScanEvidenceWorklist.tsx`: labeled native controls
  for evidence category, endpoint, scan mode, metadata search, sort,
  page size, Clear, Previous/Next, `aria-live` count, and real
  received-record summary. Missing report state never becomes zero
  scanner failures, agent protection, or clean endpoint count.
- `frontend/src/scan-evidence.ts`: pure classifier, filter, summary,
  deterministic sorting, bounded paging. No API calls or privileged
  action surface.
- `frontend/src/scan-state.ts`: aligned classification for
  unsupported quick/full and unknown-mode successful verdicts;
  `scan-history.ts` synchronized for compatibility.
- `frontend/src/main.tsx`: replace previous unfiltered job table
  without altering API fetch logic or authentication origin policy.
- `frontend/tests/scan-evidence-render.test.mjs`: React SSR
  verification for labels, live counts, 25-row page, XSS-safe text,
  empty/error/unsupported claims and no endpoint action controls.
- `frontend/src/styles.css`: original mobile, dark/light,
  forced-colors and visible-focus treatment.

## Independent release gates

**Agent 1:** Security semantics, especially no quick/full success,
ClamAV source authenticity, path scanning race/TOCTOU, engine
provenance and false positives.

**Agent 2:** Production tenant-/device-scoped signed scan requests,
per-platform capability negotiation, durable queue/paging, scan
signatures, DB integrity/freshness and typed verdict provenance.
The UI cannot substitute for these services.

**Agent 3:** Real browser keyboard/AT/zoom/forced-colors, malicious
metadata strings, cross-tenant/device API negative tests, EICAR
using a real ClamAV engine and corrupted/expired DB, daemon failures,
disconnected/expired leases, Windows/Linux endpoint smoke. Node SSR
and Windows build CI are not real-host testing.

**PM:** Stack this draft PR on #100/#76/#55/#49, reconcile concurrent
scan fixes #53/#54, request independent review and keep release
blocked until signed off. No merge or deployment is authorized by
this document.
