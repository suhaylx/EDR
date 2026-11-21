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
