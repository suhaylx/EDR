# TuranSec EDR - Security Functionality Specification (Agent 1)

Status: Lab design + one read-only Go correlation prototype, 2026-11-21.
This is not a released AV/EDR engine, and the role persona is a simulated
senior-practitioner quality benchmark, not a claim of employment history.

## Ownership

Agent 1 owns practical security functions, original detection-rule content,
threat models, expected alert semantics and security tests. Agent 2 owns Go/Rust
integration and deployment; Agent 3 validates functionality; Agent 5 implements
UI controls. PM tracks evidence and acceptance.

## P0 - trustworthy security control plane

- One Rust agent identity per endpoint, bound to tenant and device via mTLS.
- Signed tenant/device-scoped commands with expiry, nonces and anti-replay.
- Immutable signed policies, bounded local execution, audit, offline handling.
- Managed tamper policy: unauthorized local disable/uninstall denied subject
  to platform limitations; signed one-time maintenance authorization.
- A ClamAV or Sysmon worker failure must not crash the Rust core.

## P1 - real security functions

- ClamAV: quick/full/custom/scheduled scans, official signature DB updates,
  bounded CPU/I/O/archive/time, explicit scan errors, history and cancellation.
  Clean-by-signature does not imply safety. EICAR is the safe AV test fixture.
- Static: locally inspect PE/DLL/ELF structure, hashes, signer trust where
  available, imports/exports, entropy and provenance; no sample execution.
- Sysmon: use Event 1 process start, Event 11 file creation and actual Event 7
  DLL ImageLoad for Windows, with sensible event volume limits. Event 11 alone
  cannot prove DLL execution. Linux telemetry capability must be checked.
- Correlator: `backend/internal/edr/detection.go` currently generates a
  LOW-confidence, MEDIUM-severity alert for actual observed Windows module
  loads from likely user-writable paths. It may optionally link a prior
  file-create event on the same device and path. No automatic remediation.
- Response: reversible quarantine first, evidence and rollback, restore by
  authorization; no irreversible deletion by default. Real-time prevention
  needs actual OS mechanisms before it can be claimed.

## Prototype interface (DEVELOPMENT ONLY)

`GET /api/detections` returns `[]Detection` with rule ID, source load event,
optional source file-create event, process identity and module path.
The endpoint uses the existing development-only bearer token, and events
originate from an in-memory, unauthenticated-device lab model. This is NOT a
production-safe source of detections and cannot be deployed to customer hosts.

### Event provenance fields (laboratory only)

Ingested `Event` records include `received_at` (server-stamped UTC receipt
instant), `time_origin` (`sender_reported_unverified` or `server_received`),
and optional `source_record_id` (up to 256 bytes, no control characters, DEL or Unicode replacement character). The existing
`time` field is a sender-provided observation time when supplied; otherwise
it falls back to receipt time. Incoming `received_at` and `time_origin`
values are overwritten server-side. The server-generated `id` is an ingest
record ID, **not** a source Sysmon EventRecordID. The optional source record
identifier is an unverified sender claim, not cryptographic provenance.

These fields improve investigative transparency only: they do not implement
mTLS, source authentication, tenant scoping, replay protection, boot/session
identity or tamper-proof evidence. Detection remains provisional and must not
be used to trigger automated remediation.

`GET /api/detections` now also exposes `load_source_record_id` (when supplied),
`load_time_origin`, and `load_received_at` for the originating module-load
record. These are informational fields: the sender-reported record ID and
observation time remain untrusted, and the server receipt timestamp is not
proof of the event's authenticity. Missing optional fields must never be
presented as validated evidence by the SOC UI.

### QA acceptance

1. FileCreate without ImageLoad => zero detections.
2. ImageLoad of DLL from user-writable location => one provisional detection.
3. Optional FileCreate linkage => same device, same normalized path, correct
   temporal order within 24 hours, compatible hash when both exist.
4. Cross-device events and Linux events cannot cause Windows rule matches.
5. Duplicate input ImageLoad records do not double-count in one evaluation.
6. System32 DLL does not match; alerts never claim malware is confirmed.
7. Unauthenticated GET /api/detections is rejected.

## Production blockers

No mTLS device identity, durable storage, event signatures, Sysmon collector,
reliable de-duplication across reboots, signer verification or real ClamAV
scanning yet. QA must execute Windows/Linux fixtures before broadening rollout.

### Boot-scoped evidence correlation (lab)

Events may carry an optional `boot_id` (maximum 128 bytes). This is a sender-reported, **unauthenticated** boot/session marker, not an attested Windows boot identity. The DLL-load heuristic emits a low-confidence signal on an eligible ImageLoad even without this marker, but only attaches earlier file-create evidence when **both** events provide the **same nonempty** `boot_id` as well as matching device, path, time window and compatible hashes. Missing or different boot markers must not create a file-to-load linkage. This prevents some cross-boot false correlations, but does **not** authenticate a device, prevent spoofing, or provide durable replay protection.

## SEC-001 / AV-002 — Versioned functionality contract v2 (2026-11-21)

**Status: requirements plus executable lab rule fixtures only. No verified endpoint
protection, signed commands, real ClamAV databases or authenticated event source.**

### Capability state and trust

For each OS/component expose not_instrumented, unsupported, configured,
operational, degraded, failed, or unknown. Operational requires a fresh
authenticated collector/scanner health observation and applied policy
revision; server heartbeat alone is never evidence of active protection.

### Agent 2 — signed scan job contracts

Request (schema_version=1): request_id/idempotency key, tenant_id,
target_device_id, profile (quick/full/path/scheduled), actor_id, reason,
policy_revision, deadline_utc and approved logical scan root IDs. Go must
derive tenant membership and RBAC from authenticated context, not JSON.

Lease: server-signed command_id, tenant_id, device_id, profile, permitted
root, issue/not-before/expiry timestamps, nonce, policy digest, max_file_bytes,
max_total_bytes, max_files, max_archive_depth, concurrency and wall_timeout.
No arbitrary path or quick/full success without policy-backed traversal.
Device validates signature and persists anti-replay state across reboots.

Result: scan_job_id, lease_id, attempt, agent_id, engine=clamav,
engine_version, official DB version/age, start/end timestamps, coverage
(complete/partial/none), examined/skipped counts, byte counts, scanner
errors, verdict, signature name only for a positive, and source attestation.
Store server receipt timestamp separately; do not allow wrong-agent, expired
or duplicate completion to rewrite the verified attempt. State transitions:
queued -> leased -> running -> completed/failed/cancelled/expired.

Verdict invariants: malicious only on a named actual ClamAV signature hit;
clean_by_signature only for fully and successfully scanned requested scope
(no assertion of safety); error for a scanner/daemon/parse/timeout failure;
unscanned for a job that never ran. Partial work is never silently marked
clean or complete. Distinguish file skips, size limits and encrypted content.

Profiles: quick = signed versioned high-risk root set; full = authorized
local fixed volumes with explicit exclusion and no implicit remote shares;
path = root-scoped named target; scheduled = bounded replay-safe policy
trigger with offline catch-up, jitter and concurrency limits. Unsupported
profiles return unscanned, never fabricated success.

ClamAV 1.5.5 is the sprint validation baseline, NOT proof that it is
installed. Maintain official FreshClam database integrity and staged updates,
record engine/DB versions, update failures and freshness, retain last known
good, protect update channels. Use local Unix socket or loopback-only clamd,
INSTREAM with max less than configured StreamMaxLength, explicit
connect/read/write AND total wall-clock timeouts, file size (lab 128 MiB),
decompression/recursion and CPU budgets. Malformed replies and daemon
errors cannot result in clean_by_signature. Linux must open beneath a
trusted policy-root handle with kernel-backed path resolution; Windows
must use reparse/ADS/device-safe handle access and verify file identity,
size and type after open. Mutable contents, inaccessible files, hardlinks
and mount races need explicit protection or reported scan uncertainty.

### Local static PE/DLL/ELF analysis (planned)

Hash bounded opened file; inspect PE headers, machine type, sections,
imports/exports, executable flags, overlays, entry point, signed publisher
and Authenticode trust chain (valid/invalid/unsigned/unknown), and entropy.
Compare loading-process identity and module location with observed EID 7.
Mark heuristic confidence low without stronger corroboration. Never execute
samples on endpoints; isolate any optional dynamic sandbox off-host. Bound
parser memory/time and disclose errors and missing platform capability.

### Original DLL detection v2 — code and traceability

See rules/windows/dll-sideloading.yaml and
tests/fixtures/security/dll-correlation-v2.json (17 safe metadata cases).
Go fixture test executes the actual low-confidence DLL heuristic. EID 11
file creation is not EID 7 module execution. Missing EID 7 is NOT proof
of safety. Current source IDs and boot IDs are sender-reported, not
authenticated. Optional file-create enrichment requires exact same
device, nonempty same boot, consistent normalized path, prior time
within 24 hours and matching full 64-hex SHA-256. Standard Sysmon EID 11
does not itself attest a file hash, requiring separate authenticated
on-host hashing in future. The file creator and eventual loader need
not be the same process, so current conservative process-GUID checks
can lose useful links; missing correlation is unknown, not benign.
The YAML describes the rule but is not loaded by the Go rule engine.

Benign installer and updater DLL loads can trigger medium severity,
low confidence alerts. No default global suppression. Future suppression
must be tenant-scoped, rule-versioned, narrow (verified signer/hash/path),
justified, approved, expiring, auditable and retested. Never auto-quarantine
or delete on one unauthenticated heuristic.

### Quarantine, restore, tamper and Sysmon management (planned)

Quarantine uses a signed approval-gated command, verified opened file
handle, source hash/size/owner/ACL/time and case ID, encrypted restricted
storage and tamper-evident audit; capture succeeded/failed/partial/unknown.
Restore requires separate authorization, rechecks stored hash and refuses
silent overwrite of an existing path. No automatic irreversible deletion.
Local UI cannot bypass privileged service ACLs or command authorization.
Signed one-use maintenance must expire and be replay-resistant. Do not
claim resistance to a privileged OS administrator or root.

Sysmon supervisor must be separately restartable, preserve core scan
and heartbeat during malformed XML or collector crash, stage signed
compatible policy revisions and last-known-good rollback, detect
externally managed installations and refuse unapproved takeover.
Windows targeted EIDs 1/3/7/8/10/11/12-14/19-22/25/29 require
per-event coverage and dropped-record accounting; 3/7/10 are high
volume, EID 24 privacy sensitive, EID 23 archiving off by default.
Linux reports its actual collector/distro/kernel capabilities, never
synthetic Windows-EID parity.

### Implementation handoff / acceptance

Agent 2: tenant-bound mTLS enrollment and durable signed commands first;
next add ClamAV worker/version+DB reporting, source authenticated event
IDs and immutable raw evidence, event-coverage/dropped counters and
policy desired-vs-applied hashes. Device offline days use server-received
heartbeats; top rules count actual detection firings, not policy assignments.

Agent 5: display separate configured, operational, degraded, unknown and
not_instrumented states, scan partial/error/unscanned, database age,
alert severity AND confidence, authenticated evidence vs reported-only,
collector loss and graph gaps, quarantine approvals and restore outcomes.
Keep raw events separate from alerts/incidents and navigation accessible.

Agent 3: run all 17 fixture scenarios; independently test real Windows
EIDs 1/7/11, Linux sensor capability, ClamAV 1.5.5 EICAR positive and
benign negative, stopped daemon, malformed/truncated response, timeout,
wrong-agent lease, revoked cert, duplicate/replay, boot mismatch,
symlink/volume escape, oversized file, shutdown/rollback isolation,
restore collision, UI and tenant authorization. Report PASS/FAIL/NOT RUN
with build SHA and scanner/DB versions. No AV/EDR release claim until
auth, real sensor evidence, production path controls and QA gates pass.
