# Lab Windows scan target path safety policy (SEC-001 / AV-001)

This change applies only to the Go laboratory scan-job input validator. It does not establish secure Windows file-open behavior or authorize endpoint actions.

## Threat and rationale

Windows path parsing has aliases that may not identify an ordinary file target. NTFS alternate data streams (`file.exe:stream`), Win32 reserved device aliases (`NUL`, `CON.txt`, `COM1`, etc.), illegal Win32 characters, trailing dot/space normalization and embedded ASCII control characters must not be accepted as ordinary local file paths. A mistaken target could produce misleading AV results or scan something the operator did not request.

The lab API now rejects these cases for Windows *path* scans, while still allowing ordinary drive-absolute paths and Unicode filenames. Full/quick scan modes remain unsupported by the worker (PR #38).

## Acceptance cases

- Reject NTFS alternate stream syntax, including `::$DATA` and embedded component colons.
- Reject Windows device names, even with extensions and in any path component, plus COM/LPT superscript digit aliases.
- Reject empty, dot and dot-dot components; trailing dot/space, wildcard, pipe, quote, bracket operators and ASCII controls.
- Allow regular paths including ordinary spaces, Unicode, `COM10` and nonreserved prefixes like `NULity`.
- Verify rejected targets do not enqueue scan jobs.

## Remaining security gap

This validator is **not** a Windows file sandbox. Win32/NT namespace aliases, junctions/reparse points, hard links, case folding, trailing normalization and path changes between validation and use require protection at the **endpoint open** boundary, not only server-side lexical validation. Production must open a handle inside a policy-authorized directory, verify the opened object's identity/type and effective path, enforce no-follow/reparse policy and use bounded I/O. Device/tenant mTLS, signed policy, durable audit and real AV QA are not present. The API lab bearer token is not production authentication.

Agent 2: implement endpoint-side handle and reparse controls. Agent 3: run Windows Server 2022/Windows 11 integration tests including ADS, device aliases, junction escapes, case and normalization, and path-swapping races. No merge/deploy before independent QA.
