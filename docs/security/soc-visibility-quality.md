# Agent 1 — EDR Detection Quality & SOC Visibility Requirements

**Owner:** Agent 1 (Security Functionality Lead). **Status:** product acceptance requirements; a small subset is now implemented in the laboratory overview API, not as verified endpoint security.

## P0: Fleet posture and trust

- Server-received heartbeat is the sole initial source for online/offline, with a documented 5-minute grace window and explicit unknown state. Display how long each host has lacked contact, its last known server-side received timestamp and the reason when available. A user-supplied `health=online` must never override stale heartbeat.
- Later distinguish decommissioned, unenrolled, expired certificate, stale policy, disabled scanner, and telemetry-receiving-but-missing-heartbeats states so analysts avoid conflating different causes.
- For every supported OS, show which ClamAV, static PE/DLL and Sysmon capabilities are **supported, actually running, degraded or unverified**.

## P0: Real alerts and rule quality

- Preserve a separate `raw event -> detection -> incident -> response` record; never count raw Sysmon events as high-severity alerts or a created DLL as an executed module.
- Severity buckets `critical/high/medium/low/informational` are based on actual detection records; no raw network connection can manufacture a critical incident.
- 'Most used rules' must mean observed rule firings, not enabled policy count. Show a separate applied-policy coverage widget to avoid analyst confusion.
- Record stable rule ID/revision, severity, confidence, detection evidence links, scan/verdict origin (ClamAV vs TuranSec static vs observed behavior), suppression state and review outcome.
- Compare rates against collector reliability, observed agent count and false-positive feedback. A rising alert count could indicate noise, better coverage or actual threats.

## P1: Protection efficacy and missed signals

- ClamAV last successful scan, official database version/age, update failures, timeouts, scan size limits and worker health. `clean_by_signature` is not an all-clear. Flag when a scan was requested but no authenticated agent result exists.
- Sysmon process-create (1), image load (7), file-create (11), DNS (22) and network (3) support status by platform, plus explicit event loss, backpressure and failed configuration/rollback; avoid claiming Windows Sysmon Event 7 is always enabled.
- Persistence/audit, tamper protection and maintenance bypass attempts, unsigned policy mismatch, privileged command failures and quarantine/restore failures require their own operational alerts.
- Incident response hygiene: high-severity untriaged age, mean/median acknowledgement and response times, false positive rate by rule, top hosts by distinct detections per host (not just raw event volume), and alert-to-incident groupings.

## Privacy and performance

- Tenant and device scope must be enforced in authenticated Go API queries before external exposure. The browser cannot be trusted to filter private event results safely.
- Avoid uploading sensitive file content when metadata is sufficient; mask command lines and DNS details by customer policy. Show telemetry sampling/drop flags so users can judge quality.
- Keep dashboard queries bounded and compute aggregates in durable backend storage when event volume grows. No unbounded client aggregation for enterprise fleets.

## QA gates

1. Expired/unknown heartbeat must not be shown online, regardless of client-reported health.
2. Offline duration is deterministic and shows the original last-contact time, including devices offline for weeks; a zero timestamp shows unknown.
3. A `file_create` alone yields **no** DLL-execution detection, severity or rule hit.
4. Same-device observed `module_load` may yield a provisional low-confidence detection; never infer high severity from network activity alone.
5. Rule-hit counts must match actual detection records and avoid mixing policies.
6. Missing telemetry shows 'not instrumented/unverified', not a safe green badge.
7. Unauthenticated requests and unsupported time-window values are rejected; future production uses server-side tenant/role scopes.
