# SYS-003 milestone 4 — NTFS alternate-data-stream creation (EID15)

**Scope:** Original TuranSec read-only laboratory heuristic. Windows Sysmon Event 15 FileCreateStreamHash reports a new named stream; it does **not** prove execution, file compromise, successful injection or malware.

`TURAN-WIN-ADS-STREAM-001` requires a reported Windows EID15 file_create_stream_hash record, nonempty boot/process/source record provenance, complete normalized SHA-256 string, a drive-absolute named NTFS alternate-stream path, and a base file in a potentially writable directory. It excludes `Zone.Identifier` (Mark-of-the-Web), `WofCompressedData` and common summary metadata streams, as well as malformed/relative/UNC paths. Source-rec ID and hashes are unauthenticated lab claims; a hash's syntax is not verified content.

Output has `stream_event_id`, `stream_path`, `stream_name`, medium severity, low confidence, no automatic remediation, ATT&CK T1564.004 hypothesis only. The work uses no file operations, test malware or NTFS streams created on a host.

**QA:** synthetic EID15 normal and `:$DATA` forms, 20 negative cases covering MOTW, wrong event ID/type, missing provenance/hash, unrelated system path, malformed stream and cross-boot dedup, plus lab API dev-token access. Agent 2 must normalize real Win32/NT namespace stream paths, Sysmon hash field and source identity with privacy/tenant authorization. Agent 3 must verify benign ADS corpus and real EID15 from Windows Server 2022 and Windows 11 before approving collection or alerting; measure volume and false positives. Agent 5 must explicitly label EID15 as *stream created*, **not executed**.

**Blockers:** original Sysmon source is not authenticated; no live collector, durable queue, mTLS tenant binding, signed policies, independent QA or release approval. Review stack: draft PR #99 -> #93 -> #85 -> #63 -> #60 -> #29 -> lab MVP #5.

Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
