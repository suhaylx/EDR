# Agent 5 bug fix — truthful scan-result detail (22 Nov 2026)

**Scope:** private `suhaylx/EDR`, React read-only lab interface only.
Stack: this branch on draft QA PR #169 → #166 → #158 → #151.
No automatic merge, signed scanner result, endpoint action or production deploy.

## Reproduced defect

`frontend/src/scan-evidence.ts` already required a reported
`scan_type === "path"` before classifying a completed positive result
as a plausible **reported** signature match, suspicious finding or
signature-negative scan. But `frontend/src/scan-state.ts` separately
rendered details as **"Clean by signature (reported)"** or
**"Signature match reported"** without requiring a supported path
mode. For a missing, unknown or differently cased scan mode, the
worklist and the detail screen contradicted each other. A completed
`malicious` row with **no signature indicator** also received the
"Signature match reported" heading.

This can mislead an SOC analyst into treating malformed or
capability-unsupported metadata as meaningful scan evidence.

## Fix

- `describeScan()` now refuses positive-looking `malicious`,
  `suspicious`, or `clean_by_signature` verdicts unless
  `scan_type === "path"`; missing/unrecognized modes become
  **"Result not verified"**. Unsupported quick/full claimed successes
  keep their more-specific **"Unsupported scan claim"** warning.
- A path-mode `malicious` verdict without the reported signature
  indicator is now headed **"Malicious verdict lacks signature
  evidence"**, not "Signature match reported".
- A reported signature indicator can still produce the cautiously
  worded "Signature match reported", **never attested** and with
  the raw signature name withheld.
- Scanner `error` and `unscanned` verdicts keep their negative
  classifications regardless of mode.
- `SCAN_FLAG_LABELS` describes signature **indicator** metadata
  instead of assuming a raw signature name is delivered.
- `frontend/tests/lab-api.test.mjs` expected object shape
  now includes `expires_at`, `lease_until`, `completed_at`
  fields introduced by the prior scan lifecycle sprint.

## Reproducible focused verification

In an isolated local Node 22 / TypeScript environment, the exact
committed code and test bytes were manually materialized and compared
with GitHub's git blob hashes:

- `frontend/src/scan-state.ts`:
  `5d25c1ab76e4d1b5a9602d98f9fbb4cf09b15200`
- `frontend/tests/scan-state.test.mjs`:
  `a299f29e12d73576a396e65c38ff04f30ec4f730`
- `frontend/src/lab-api.ts`:
  `53b7abce08a53538381271af63ccd7d52c176f75`
- `frontend/tests/lab-api.test.mjs`:
  `d75b19ef02b0b01674e9c2c533e1430e8702720e`

Commands:

```sh
tsc src/scan-state.ts src/lab-api.ts --module Node16 --moduleResolution Node16 --target es2022 --strict --skipLibCheck --outDir .test-dist
node --test tests/scan-state.test.mjs tests/lab-api.test.mjs
```

**Result: 17 tests passed, 0 failed; strict TS compilation passed.**
The five new scan-display test cases include multiple missing/unknown modes,
quick/full contradictions, malicious-without-signature, name privacy,
and scanner error/unscanned precedence. Five existing scan-API decoder tests
also passed, including the corrected lifecycle-field expectation, strict
metadata-only GET and invalid bearer response handling.

**Not verified:** Full React build, all frontend tests beyond the two isolated targeted suites, actual browser/manual screen-reader QA,
complete Go/Rust/Windows/Linux backend suite, signed endpoint scan
provenance. GitHub Actions has suffered zero-step runner allocation
failures (DevOps #153), so an exact-head CI status must be checked
on the new pull request before any merge. Agent 3 QA and Agent 1
InfoSec should inspect and approve the wording and capability truth.
Production release remains NO-GO.
