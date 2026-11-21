# SYS-003 milestone: Sysmon process + DNS + connection correlation

**Status:** Original TuranSec laboratory detector, review only. Backed by the draft PR from this branch; depends on provenance fields in PR #29. No live Sysmon collector exists in this increment. Synthetic fixtures are not proof of detection on a real Windows host.

## Implemented contract

The Go `Event` model adds `sysmon_event_id`, `dns_query`, `dns_answers`, `destination_ip`, and `destination_port`, with size and syntactic validation. The in-memory receipt ID is created server-side; `source_record_id`, `boot_id`, `source` and event time are still unverified sender claims. This is not tenant isolation or source attestation.

Rule `TURAN-WIN-PROC-DNS-NET-001` requires all three *separate* events: Sysmon **EID 1** process start of an executable in a likely user-writable path; **EID 22** DNS query with an IP answer; **EID 3** network connection to the **same IP**. Correlate only when device ID + nonempty reported boot ID + process GUID match, EID 1 <= EID22 <= EID3, process->DNS <=5 minutes, DNS->network <=2 minutes, process->network <=6 minutes. Require distinct event type/EID and nonempty sender-reported source record IDs; only public non-private unicast IP destinations with positive ports are evaluated. IPv6 is supported. Deduplicate one provisional alert per reported process/boot. No alert for any incomplete pair, a private/proxy destination, System32 process, wrong source/EID, or mismatched DNS answer.

The output provides **three separate ingestion record IDs**, DNS name, destination IP/port and an explicit explanatory caveat. Severity **medium**, confidence **low**, action **alert only**. DNS resolution does **not** prove a connection; the EID3 observation is required. An observed connection and DNS match do **not** prove infection, command-and-control, or even application-layer communication. A matching answer may be cached, shared by several queries or distorted by proxies/NAT. No auto-quarantine.

## Synthetic QA and limitations

Unit tests cover all three event requirements, missing/cross-device/boot/process source claims, event-ID mismatch, DNS IP mismatch, missing answers/port, remote scope, elapsed-time violations, event order and duplicate handling, IPv4/IPv6, malformed network data, and `GET /api/detections` development-token denial/authorized retrieval.

**Not yet implemented:** live Windows EID1/3/22 collection, Sysmon configuration/deployment or high-volume measurement; signed source provenance; tenant ID; server-validated device/boot identity; durable bookmark/replay; actual process signer/hash trust; DNS caching/proxy attribution; Linux parity; disk-backed correlation windows. Source EventRecordIDs and the boot marker are unauthenticated strings in the lab. No production deployment.

Agent 2 must add mTLS-bound tenant/device collection, verified Sysmon source and version, durable queue/bookmarks, bounded retention, event-loss indicators and policy coverage. Agent 3 must run real Windows Server 2022 and Windows 11 fixtures, benign updater false positives, high-volume EID3 rate tests, out-of-order ingest, restart/replay and cross-tenant negative cases. Agent 5 must render an *observed vs inferred* evidence chain and uninstrumented coverage, never a confirmed infection.

## Related milestones

PR #29 provides lab event receipt provenance; PR #14 provides broader Sysmon collection design. Full real deployment is blocked until Agent 2/3 authenticate and validate the end-to-end telemetry chain. This work does not displace P0 enrollment and persistence (issues #1-3).
