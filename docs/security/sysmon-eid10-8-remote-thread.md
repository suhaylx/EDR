# SYS-003 — TuranSec EID10 + EID8 process interaction rule

**Implementation status:** Lab-only, read-only heuristic on a review branch, stacked on Sysmon EID1/22/3 PR #60, which depends on source-provenance PR #29 and lab MVP PR #5. The repository does not yet establish real Sysmon collection or trusted device identity. This file does not claim that process injection, malware activity, or an attacker has been observed.

## Observed signals versus hypothesis

Windows Sysmon **Event 10 (ProcessAccess)** records a process opening/accessing another process. Access rights in `GrantedAccess` indicate handle permissions, not that memory has been read, modified or injected. Windows Sysmon **Event 8 (CreateRemoteThread)** separately records one process creating a thread in another process; `NewThreadId` is the reported thread ID. A thread creation event does **not** prove malicious code injection. Correlating both supports a **T1055 Process Injection investigation hypothesis**, not a confirmed ATT&CK technique.

Microsoft Sysmon documentation: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
Microsoft process access rights: https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights

## Proposed normalized laboratory fields

The Go `Event` contract gains `source_process_guid`, `target_process_guid`, `granted_access` (0x-prefixed unsigned 32-bit hex) and `remote_thread_id` (uint32). These are bounded and syntactically validated, and remain unverified sender claims. If the generic `process_guid` is present for an EID8 or EID10 record, it must agree with `source_process_guid`.

The Go detector `TURAN-WIN-PROC-REMOTE-THREAD-001` requires both independent records, with numerical EIDs 10 and 8 and matching declared event types. Both records must have nonempty sender-reported source record IDs, distinct from each other. Join on reported device, nonempty boot ID, source GUID and target GUID. Source must differ from target. The EID10 record must precede EID8 by **0–120 seconds**, and EID8 must have nonzero `remote_thread_id`. The EID10 access bitmask must include all `PROCESS_CREATE_THREAD=0x2`, `PROCESS_VM_OPERATION=0x8` and `PROCESS_VM_WRITE=0x20`. Mask bit presence is a coarse triage filter; it does **not** prove memory operations took place.

`GET /api/detections` exposes `process_access_event_id`, `remote_thread_event_id`, source and target process GUIDs, original access mask and thread ID, with confidence **low** and severity **medium**. These event IDs are *server receipt IDs*, not Sysmon `EventRecordID` or cryptographic source evidence. The rule is **alert-only**, with at most one signal per reported device/boot/source/target pair in one evaluation; the inputs are sorted to avoid out-of-order or duplicate alert inflation.

## False-positive controls and residual risks

Suppress alerts caused by read/query-only handles, missing or invalid rights, self-target access, wrong/missing event ID/type, missing event evidence, mismatched source/target, cross-device or reported boot scope, stale/reversed time, repeated input or repeated same process pair. Do not create a blanket exclusion for antivirus, EDR, debuggers, profilers or operating-system processes: those can legitimately perform remote-thread operations, but paths alone do not prove trusted origin. Production allowlists need signed policy, device/tenant scope, genuine signer and reproducible benign evidence.

There will be both false positives (debuggers, accessibility, security products, instrumentation) and false negatives (other injection approaches, missing EID8/10, different access rights, longer time windows, filtered sources). EID10 can be high-volume; enable with selective and measured rules in a QA canary, not all-host logging by default. No automatic quarantine or prevention is implemented.

## QA and release gates

Synthetic tests cover EID10-only/EID8-only, valid pair, each missing or mismatched source/device/boot/process/event ID, same record ID, missing or invalid access mask, partial or query-only rights, missing thread ID, incorrect order/window, duplicate and shuffled inputs, nearest qualified access selection, incorrect/malformed incoming fields, and development API authentication. Passing unit tests do **not** validate a real Windows telemetry pipeline.

Agent 2 must implement authenticated and tenant-bound source ingestion, signed policy/capability provenance, live Sysmon subscriber with source channel/record/version, durable event queue/bookmark and retention, proper validation of `NewThreadId`, event loss counters and safe EID10 policy tuning. Agent 3 must independently test benign debugger and AV scenarios, synthetic EID10+8 positives and negatives, Windows Server 2022/Windows 11 capture, missing EID8, source-record replay, tenant/device/boot isolation and performance. Agent 5 must show the two observed events, hypothesis and missing verification state without rendering a confirmed injection.

**Production release remains blocked** on mTLS device identity, tenant isolation, durability, actual collector integration, rollback, resource budgets, independent QA and security approval. No malware execution or real endpoint action is performed by this detector.
