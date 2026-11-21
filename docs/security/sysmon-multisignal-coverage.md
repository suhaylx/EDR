# Sysmon Modular + TuranSec multi-signal detection plan

**Decision:** The product must observe and correlate security events beyond Sysmon FileCreate. **Status:** approved specification; not yet an installed endpoint collector.
**Reference:** [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular), reviewed upstream master at `a45dedb13a43c0d8ea1fc6b580a0ac396fa74457`. The upstream project contains modular **Sysmon XML configurations and a Go config-building tool**, *not* an EDR detection engine. Its MIT license requires attribution and notice if upstream files are redistributed. Do not copy Microsoft Sysmon binaries without separately satisfying Microsoft distribution terms.

## Windows telemetry beyond creation

| Event IDs | Sensor | TuranSec use |
| --- | --- | --- |
| 1, 5 | ProcessCreate / terminate | Actual parent-child lineage and execution history |
| 3, 22 | NetworkConnect / DNS | Process-to-destination and resolution context, never assume a DNS query implies a connection |
| 7 | ImageLoad | Observed DLL/module load; Event 11 file creation **does not prove execution** |
| 8, 10 | CreateRemoteThread / ProcessAccess | Supporting evidence for possible injection and credential-access patterns, with benign-app exceptions |
| 11, 15, 29 | FileCreate / ADS / FileExecutableDetected | Executable and DLL staging, alternate streams, provenance |
| 12, 13, 14 | Registry changes | Autorun, service and other persistence hypotheses |
| 17, 18 | Named pipe created/connected | Inter-process communications and selected lateral-movement hypotheses |
| 19, 20, 21 | WMI activity | Persistence via filter/consumer/binding; requires role-specific tuning |
| 25 | ProcessTampering | Defense evasion evidence and tamper-health correlation |
| 2, 6, 9, 23, 26 | Timestamp changes, driver load, raw disk access, file deletion | Advanced capabilities with OS/version/volume/privacy guards |

Event 24 ClipboardChange is **off by default** due to privacy impact. Event 23 FileDelete archiving is **off by default** due to disk/custody cost. High-volume events 3, 7 and 10 require selective collection rules, measured resource budgets and opt-in investigation profiles. Linux Sysmon, eBPF and audit coverage must be declared separately; do not assert Windows event-number parity.

## Essential EDR model

Endpoint Rust core maintains independently running ClamAV scanning and platform telemetry collectors. Agent 2 owns authentication, signed policies, source event normalization and a bounded durable offline queue; Go backend owns tenant/device validation, deduplication, immutable raw evidence, versioned detections, incident records and an auditable response path.

Required event identity: tenant/device, Sysmon provider and numerical Event ID, source channel + RecordID, event/source timestamps and server receipt, process/parent GUID (with session/boot ID if needed), file path + hash, module load path, actor/target process, DNS/network/registry/pipe/WMI fields, original payload provenance, configured-versus-actual capability and loss counter. The lab `Event` type currently lacks most of these and uses **in-memory retention of 2,000 events**; this is not a shipped correlation model.

**Core correlations:** observed process execution → file writes → actual module/executable loading → outbound DNS/network; alternate branches for remote-thread/process access, WMI/registry persistence, file deletion, suspicious drivers and tampering. A detected event is never automatically a confirmed infection. Model `observed` relationships separately from `inferred`/low-confidence hypotheses; all edges link original event IDs and visible gaps. See the dedicated **process and incident graph** implementation task for the analyst's complete infection-story view.

## Profiles, delivery and QA

1. **Balanced workstation:** Event 1 and 5, selective 3/22, 11 and 7, targeted 12–14 and 25, version-dependent.
2. **Server/domain controller:** role-specific allowlists, tuned process and egress collection without wholesale blind exclusions.
3. **Short investigation boost:** time-limited elevated 7/8/10, 17–21, 26 with CPU/I/O/volume caps, policy expiry and safe rollback.
4. **Linux:** distro/kernel/collector version gates and observable missing-capability states.

Version pin XML schema and Sysmon build. When adopting upstream generator, validate/analyze/diff/coverage **before** staged canary and rollback; generated ATT&CK coverage doesn't imply actual detection or interception.

**Agent 1:** Original versioned rules for process-to-network, image-load side-loading, process access/remote thread, WMI/registry persistence, and tamper; positive and benign fixtures, suppressions, severity/confidence.
**Agent 2:** Authenticated normalized ingestion, durable bookmarks, deduplication, source evidence, process graph joins and runtime coverage/agent health; no broad WinAPI hooks.
**Agent 3:** Same-device and process-scoped joins, cross-tenant negative tests, reordered/dropped events, FileCreate-without-ImageLoad, false-positive filters, load/retention performance, canary rollback; real endpoint tests `NOT RUN` until executed.
**Agent 4 PM:** Technical tickets, role-specific proof and timely reviewable commits; no fake hourly GitHub writes.
**Agent 5:** Show collection coverage, exact events and correlations, missing-signal warnings and the source-linked incident tree.

**Release gates:** actual Sysmon collector and version proof, a stable authenticated device identity, durable event recovery, a measured fleet resource budget and Windows/Linux lab QA. No automatic quarantine on single low-confidence telemetry.
