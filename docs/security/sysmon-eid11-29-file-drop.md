# SYS-003 Milestone 5 — executable file creation and detection (EID11 + EID29)

**Status:** Original TuranSec read-only lab correlation; no Windows endpoint service or live Sysmon subscriber is implemented or tested. The rule requires independent **Event 11 FileCreate** and **Event 29 FileExecutableDetected**, reported from one device/boot/process and the same normalized drive-absolute file path within 10 minutes. EID29 must supply a syntactically valid SHA-256; if an EID11 hash is present, it must also be a valid SHA-256 and match. Restrict the first rule to .exe/.dll/.sys under likely writable directories.

**Security semantics:** EID11 alone is *a file creation*; EID29 adds a report that the created file is executable. **Neither proves the file was executed or loaded**, and neither proves malware. A missing EID29 or delayed EID29 does not prove safety: coverage and retention may be incomplete. Emit medium severity, low confidence, alert only. The separate receipt IDs `file_drop_create_event_id` and `executable_detected_event_id` must be visible in the SOC. T1105 is a candidate technique hypothesis only.

**Tests:** synthetic missing EID11/EID29, wrong source/type/boot/device/process, mismatched path/hash, invalid hash, reversed/stale observation, wrong file extension/system path, duplicate input/boot, and dev API authentication. These tests use no executable samples and no actual Windows Sysmon capture.

**Release blockers:** authenticated collector, tenant-bound mTLS, immutable source evidence, durable ingestion/retention, Sysmon 29 capability/version proof, real Windows Server 2022/Windows 11 benign installer false-positive tests, performance and rollback. Agent 2 maps real fields; Agent 3 runs QA; Agent 5 labels *file created — not executed*. No automatic response or production deployment.

Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
