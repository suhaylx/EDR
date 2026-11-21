# TuranSec local companion UI — proposed read-only v1 contract

**Status:** read-only browser status-window UI prototype and TypeScript decoding contract (Agent 5). No native tray, native app window, Unix socket, Windows named pipe, backend transport, or installed endpoint companion has been implemented in this PR. This is a **single TuranSec managed endpoint product** with a separate crash-isolated UI process; Rust remains the policy/scan authority. ClamAV and Sysmon facilities may operate as separate supervised processes or services.

## Screen model and native UX

- **Windows:** a signed, per-user unprivileged tray companion and optional status window. Show a neutral icon and accessible text describing connection state; use Windows notification and keyboard conventions, system font, system high-contrast setting, visible focus, and logical tab order. Never claim that closing the window stops protection.
- **Linux (optional):** per-user status window, with status-notifier integration only where supported. On desktops without tray support, retain a discoverable ordinary window/menu entry rather than silently hiding the status. Respect desktop dark mode, font scaling, reduced motion, and screen reader roles.
- **Status:** first surface connection state (Not connected, Stale, Reported), then core, ClamAV, telemetry, policy revision and most recent scan state. All components default to **Unknown** without authenticated current evidence. Render raw untrusted text using native React text nodes, never HTML injection.
- **Feedback:** explicitly separate queued/leased from completed and error; never equate completed or signature-negative with safety. Do not show unsupported Scan now, Quarantine, Disable, Delete, Isolate or Restore buttons. No policy switches or privileged file-system access from UI.

## Proposed IPC v1 JSON event

The exact model in `frontend/src/local-companion.ts` is a **candidate** for Agent 2 review, not an existing wire contract:

```json
{
  "schema_version": 1,
  "source": "local_agent_ipc_v1",
  "platform": "windows",
  "observed_at": "2026-11-21T17:00:00Z",
  "core_state": "reported_running",
  "clamav_state": "unknown",
  "telemetry_state": "unknown",
  "policy_revision": null,
  "scan_state": "queued"
}
```

Windows and Linux are valid values for `platform`. The proposed parser rejects unknown schema versions, invalid enum values, missing timestamp, future timestamps when presented, invalid revision, and malformed payloads. The reference presentation considers a report older than 60 seconds stale; this is a **UX threshold proposal**, not an authenticated liveness SLA. Even current reports are labeled *reported* and are not cryptographic protection attestations. A valid `source` string is not source authentication.

## Boundary and authorization requirements (Agent 2 / Agent 1)

1. Rust core owns the privileged listener; select Windows named pipe ACLs or Linux Unix socket permissions with peer-credential verification and an explicit user/session authorization model. Avoid global/world-writable IPC. The UI must not accept status from arbitrary local callers.
2. Version and bound messages, reject replay/cross-user injection, and establish freshness from authenticated transport plus monotonic session sequencing; wall-clock `observed_at` alone is insufficient.
3. Offer a least-privilege **read-only** status channel first. All future scan/quarantine/policy requests require separate explicit backend authorization, audit, rate limiting, and server policy enforcement. Do not grant the UI agent management credentials or privilege elevation.
4. Resolve per-platform capabilities: Windows Sysmon service verification versus Linux telemetry collector support; no Sysmon health claim on Linux. ClamAV signature DB provenance and age require dedicated verifiable backend fields, absent here.
5. On IPC disconnect, timeout, crash, unsupported platform, malformed data, core restart or version mismatch, clear previous reported state and show **Unavailable/Unknown**, never a green protection badge. A companion crash must not terminate the Rust core.

## Acceptance and release gates

- **Implemented as source/test spec:** `frontend/src/local-companion.ts`, `frontend/tests/local-companion.test.mjs`; tests exercise missing connection, future/stale reports, invalid schema/origin label, unsupported state and malformed payload.
- **Not implemented:** actual IPC, local process, UI tray, notification permission model, signatures, install/uninstall, scan commands, authenticated state, live component health or production deployment.
- **Agent 3:** independently verify native keyboard/AT with NVDA/Windows High Contrast and Orca/Linux when a companion exists; ensure 200% zoom, error/focus announcements, no green on failure, XSS-safe rendering, IPC tamper and denial, crash isolation.
- **Agent 2:** approve/revise transport and field semantics before connecting the UI. **Agent 1:** approve component health provenance and response authorization. **PM:** maintain draft review gates and coordinate dependency PRs.

Design principles follow clarity, hierarchy, feedback, accessibility, privacy, and adaptive native behavior from Apple HIG without copying vendor visuals/assets or overriding Windows/Linux conventions.

## Implemented browser status-window prototype

A separate Vite page `frontend/local-companion.html` is now built from
`frontend/src/local-companion-main.tsx` and renders
`frontend/src/LocalCompanionView.tsx` with responsive,
system dark/light and forced-colors-aware styling. The entry deliberately
passes `null` rather than invented status data. No lab Go token, endpoint
command, network polling or IPC is used. All component evidence displays
Unknown while disconnected, and no privileged actions are presented.

`localCompanionRows` clears prior component status on disconnect, staleness
and future timestamps. The proposed Linux telemetry row never claims Sysmon
coverage. Scan queued, leased, completed, failed, expired and unknown states
remain lifecycle labels with **no verified malware verdict**; policy revision
is a reported acknowledgement, not enforced policy proof.

For independent QA: open the page via the local Vite dev server, inspect
keyboard focus/reading order, NVDA/Orca, browser 200% zoom, light/dark mode,
forced colors, long text, reduced motion, and verify no interactive endpoint
commands. The visible default disconnected state is the **only actual runtime
state wired by this page**; other states are covered by pure TypeScript tests
until Agent 2 supplies authenticated IPC. Browser/AT/manual platform testing
has not been performed by Agent 5.
