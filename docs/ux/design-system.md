# TuranSec EDR frontend design system — lab implementation and review contract

**Owner:** Agent 5 Frontend/UX. **Status:** original source-guidance document,
not a product design approval, production accessibility certification or verified
native Windows/Linux application. Applies to React laboratory SOC and the
separate, unprivileged companion **prototype**. Source of truth for design
changes is actual source/CI on the linked draft PR; this document alone
never indicates a feature is deployed.

## Intent and platform rules

Inspired by the *principles* of Apple's Human Interface Guidelines:
clarity, hierarchy, feedback, readability, privacy, adaptability and
accessibility. This is not a copy of Apple's layout, branded artwork,
proprietary assets, icons or protected product screens. SOC navigation is
original TuranSec. Windows clients must respect taskbar/tray conventions,
system text scaling, native dialogs, high contrast and NVDA. Optional
Linux UI must work without a tray on desktops that do not support one,
with GTK/Qt-compatible accessibility practices and Orca. This React
evaluation surface is **not** proof those native clients exist.

## Implemented web tokens and layout (frontend/src/styles.css)

| Variable / pattern | Current meaning | Validation required |
| --- | --- | --- |
| `--bg`, `--panel` | Page and panel surfaces, system light/dark branches | Contrast ratios in Chromium, Firefox, Windows High Contrast |
| `--ink`, `--muted` | Main and supporting typography | WCAG 2.2 AA contrast at actual 200% zoom |
| `--border` | Separation, independent of color-only status | Forced-colors / monochrome QA |
| `--focus` | 3px keyboard focus outline | Tab, Shift+Tab, logical order, no focus trap |
| `--control` | Native button/select emphasis | 44px minimum target in existing controls |
| `.panel`, `.metric-grid` | Evidence and fleet surfaces | 320px to 1440px no hidden content |
| `.table-scroll` | Wide tables with captions and column headings | Keyboard horizontal scrolling and AT association |
| `.status--neutral/warning/danger` | Status text supplements color | Labels must always carry meaning without color |
| `prefers-reduced-motion` | Disable decorative animation | Browser and OS preference QA |
| `prefers-color-scheme`, `forced-colors` | Honor system theme/contrast | Windows native high-contrast + browser |

Use native `<button>`, `<input>`, `<select>`, `<details>`, `<summary>`,
`<table>` and `<dl>` where those semantics fit. Assign explicit
`for`/`id` label pairs, `scope=col/row`, and live status messages when
the meaning of presented results changes. Focus must remain keyboard-visible;
an action that opens evidence should focus the destination heading. Native
browser and AT testing remains necessary; SSR markup tests alone cannot
certify these behaviors.

## SOC information architecture

- **Overview:** server-received heartbeat and retained telemetry counts, not
  attested protection or installed coverage.
- **Endpoints:** enrolled records, online/offline/unknown from server timestamp;
  reported policy IDs are not verified enforcement.
- **Security alerts:** heuristic detections; analyst filters are in-memory only,
  never backend tenant isolation. Unclassified severity must remain visible.
- **Sysmon/telemetry:** observed event IDs 1–29/255 and Linux events within
  at most 100 retained records; absence is **not** evidence a policy disabled
  the event or the host is safe.
- **Investigation:** same-device, bounded retained process/source evidence;
  co-observed process GUIDs do not establish causality or ancestry.
- **Scan history:** queued/leased/error/unscanned/malicious/clean_by_signature
  are separate from signature freshness and protection. Completion is not
  an authentic scanner attestation. Current Rust lab worker does not actually
  support quick/full scans; review PRs #53/#54 before merging any scan UX.
- **Local companion:** separate crash-isolated unprivileged UI process; only
  disconnected browser prototype exists. A valid-looking JSON `source`
  field is not IPC authentication. Never offer unauthorized response toggles.

## Evidence and uncertainty language

**Reported** describes what an untrusted sender or lab API claims.
**Observed in returned response** describes what this specific API response
contains. **Unknown/not instrumented/not retained** does not mean healthy.
**Authenticated/attested/verified** require explicit Agent 2 transport, schema,
identity, clock and policy evidence that is absent from these lab views.
Never show green protection, verified Sysmon enforcement, incident closure or
successful quarantine based on a React UI badge or self-reported agent field.

Source inspection must join on **Go event ID and endpoint ID** together;
Windows `source_record_id` is supplementary evidence, not a globally unique
lookup key. FileCreate Event ID 11 is not evidence of a module load (7).
Sysmon 24 clipboard body must not be rendered, retained as free-text notes,
or silently passed through the UI.

## Manual accessibility and security acceptance for Agent 3

1. Chromium/Firefox/Safari baseline keyboard Tab/Shift+Tab and all
   `<details>`, selectors, filters, pagination, alert-to-source buttons,
   back navigation and destination heading focus.
2. NVDA/Windows and Orca/Linux read headings, captions, row/column
   names, source availability warnings and `aria-live` count without
   duplicate overwhelming announcements.
3. 200% browser zoom and OS text scaling at 320px, 600px, 900px,
   1440px. Table horizontal scroll preserves data, focus and labels.
4. System light/dark, forced-colors/high-contrast, reduced motion and
   keyboard focus. Measure WCAG AA text/UI contrast; **not verified yet**.
5. Spoofed source ID, same ID wrong endpoint, malformed JSON/field,
   control-character/newline, long untrusted source fields, HTML/script
   payload, clipboard Event 24. No script execution or secret rendering.
6. Disconnect/invalid credentials, partial API failure, token update,
   UTC window change, browser reload and multi-request overlap must not
   leave an old connected/protected-looking view.
7. No endpoint actions, scan scheduling, policy bypass, incident
   closure or secret persistence without an approved authenticated backend.

## Delivery and release

Agent 2 defines production scopes, pagination, signed telemetry/protection
evidence and native local IPC; Agent 1 approves security semantics; Agent 3
runs independent QA; PM coordinates reviewed branches. No direct merge of
draft PRs or deployment to Windows/Linux endpoints. Passing CI means only
that checked source builds and tests completed for that exact Git SHA.
