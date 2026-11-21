# SYS-003 milestone 2 — WMI permanent event subscription

**Status:** Draft read-only laboratory rule; based on Sysmon Windows EIDs 19 (EventFilter), 20 (EventConsumer), and 21 (ConsumerToFilter binding). No real collector is deployed or verified. Dependency chain: draft #85, #63, #60, #29, #5.

Rule `TURAN-WIN-WMI-SUBSCRIPTION-001` requires three distinct observations: a named WMI filter (19), a named WMI consumer (20), and a binding referencing both by exact case-insensitive names (21). The filter and consumer observations must each precede the binding by 0–30 minutes. Device and **nonempty reported boot** must match; different or missing WMI names, Event IDs/types, event receipt IDs or source record IDs cannot support a match. Reordered ingestion and duplicate binding records do not multiply alerts.

**Do not infer code execution.** A permanent subscription's filter, consumer and binding can be created for legitimate management purposes. Even a full event chain is only an indicator of a possible persistence technique (MITRE ATT&CK T1546.003). Treat results as *medium severity, low confidence, alert only*. There is no auto-quarantine.

### Source/privacy contract

`Event` adds only `wmi_filter_name` and `wmi_consumer_name`, each bounded to 256 bytes with invalid control characters rejected. The collector must **not** add WQL query bodies, command-line templates, ScriptText, credentials, or other sensitive consumer content through the `detail` field; this prototype does not provide privacy classification or scrubbing of general detail. Event `id` is a server receipt; the source's `source_record_id`, `boot_id` and `source` are unauthenticated assertions. Real collector provenance, mTLS tenant binding, and durable event retention remain P0 gaps.

### QA / integration handoff

Agent 2: normalize real EIDs 19/20/21 and object names accurately, bind source identities to authenticated tenant+device+boot, retain channel/record version, ensure durable bookmarks and loss counters; enforce server-side telemetry privacy policy. Agent 3: Windows Server 2022/Windows 11 canary for benign management tools, duplicate and cross-boot rejection, malformed WMI consumer data, real EID21 names, 30-minute boundary, restart and replay tests. Agent 5: display three separate evidence receipts, the unverified source warning and a **possible** persistence hypothesis, not confirmed execution.

Synthetic tests cover EID19/20/21 complete chain and missing/wrong/duplicated evidence, case variation, mismatched source device/boot, future/out-of-window events, malformed names, read-only API contract and dev auth. No production release, merge or endpoint deployment is authorized on unit-test evidence alone.

Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
