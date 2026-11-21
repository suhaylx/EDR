# SYS-003 milestone 1 — Registry autostart persistence hypothesis

**Status:** Draft, laboratory read-only prototype. Stacked on PR #63, #60 and #29, eventually on the lab MVP PR #5. The Windows Sysmon collector, authenticated device identity and durable event queue are not implemented here.

## Event semantics and data minimization

According to Microsoft's Sysmon event reference, EID **12** reports Registry object creations/deletions, EID **13** reports value sets and EID **14** reports key/value renames. This detector does **not** infer a Registry write from an object creation or rename. Primary signal requires **EID13 SetValue** to an exact named value under HKCU/HKLM/HKU Software\\Microsoft\\Windows\\CurrentVersion\\Run or RunOnce (with supported WOW6432Node branch), by a process image in a potentially user-writable directory. Event 12 create_key and Event 14 rename_value may enrich the EID13 within 10 minutes, only with same reported device, boot and process, exact key/value and distinct source record IDs. EID12/14 without EID13 produce **no detection**.

The proposed `Event` fields are `registry_target`, `registry_new_name` and `registry_operation`; malformed, overlong and control-character values are rejected. **Do not collect Registry value contents or secrets** in this increment. The detector has no proof the value data was executable or that the value was ever invoked.

## False positives / confidence

Legitimate installers, auto-updaters, profile helpers and accessibility software routinely set Run values. This first heuristic filters to source executables in likely writable directories, excludes unrelated Registry paths, delete actions, read-only/no-op evidence, system-directory source processes, and requires event provenance labels. It does not yet validate signatures, parent chain, vendor allowlists, value contents or installed business software; those would need signed policies and Agent 3 benign fixtures. Severity medium, **confidence low**, alert only, no auto-remediation. MITRE ATT&CK T1547.001 is an **unconfirmed hypothesis**.

The current `source_record_id`, `boot_id`, `source` and client timestamp are unauthenticated sender claims. The event `id` is a server-generated receipt ID. No tenant boundary or event attestations exist. The lab event retention cap of 2,000 may lose the correlation context.

## Review and QA

Synthetic tests: EID13-only valid provisional alert; optional linked EID12/14, malformed metadata, wrong events/operations, same-boot/source checks, out-of-order, deduplication, exact Run path matching, no EID12/EID14-only alert, false-positive/system process cases, and `GET /api/detections` authentication. Test fixtures contain only benign paths and no executable payloads.

Agent 2: real registered Windows Sysmon 12–14 source ingestion with signed collector/device provenance, EventRecordID/channel, field mapping and privacy policy; durable queue, tenant authorization, restart bookmarks, event-loss status. Agent 3: Windows Server 2022 and Windows 11 benign installer/updater false-positive corpus, multi-user HKU profiles, event 14 new-name parsing, clock skew and reboot cases. Agent 5: render observed Registry value set versus hypothesized persistence and missing value contents as `NOT COLLECTED`.

**Not production-ready** without QA, authenticated enrollment, actual Sysmon collection, durable storage, and release approval. No real host changes made.

Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
