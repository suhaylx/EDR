# SYS-003 Milestone 3 — Process image tampering (EID25 + EID1)

**Status:** Original TuranSec laboratory detection, review only. Stacked on WMI PR #93 and previous lab PRs. No endpoint Sysmon subscriber, signed source, tenant identity or verified Windows event capture yet.

Sysmon Windows **Event 25** reports process tampering. The Go prototype requires a normalized `tamper_type: image_replaced` event *and* an independent **Event 1** process creation on the same reported device, boot, process GUID and normalized image. The Event 1 observation must occur within 24 hours **before** Event 25. Require different nonempty sender-reported source record IDs and separate server ingest IDs. Treat `image_locked`, `other`, EID25-only, mismatched event IDs, stale records or Linux events as insufficient for this narrow rule.

**Interpretation:** Even if both events are observed, process image replacement is not automatically malicious and does not prove code injection, payload execution or successful evasion. Report **HIGH severity, LOW confidence**, read-only/alert-only, no auto-quarantine. EID25 type normalization must be mapped from a tested Sysmon collector version; missing capability or event loss are not negative evidence. Event IDs and time from the lab sender are not authenticated; server receipt ID is not Sysmon EventRecordID.

**QA:** Synthetic tests for complete EID1/25 pair, missing/mismatched device/boot/process/image/source/EID/type, only `image_replaced`, wrong event order and 24-hour boundary, dedup and reordered input, malformed type ingestion and dev API authorization. Agent 2 supplies authenticated and durable collector semantics and type mapping. Agent 3 must validate Windows Server 2022/Windows 11 actual EID25 cases and benign false positives before enabling. Agent 5 must show the two evidence IDs and a *possible process tampering* interpretation rather than a confirmed infection.

Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

**Production release blocked:** no mTLS device enrollment, tenant isolation, durable evidence, measured event budgets or independent QA. This rule does not remediate.
