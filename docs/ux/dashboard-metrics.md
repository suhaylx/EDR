# TuranSec SOC Overview — Metrics Contract and Acceptance

**Status:** First implementation in a localhost-only in-memory lab API + browser dashboard. The event source has not been authenticated through mTLS and must never be presented as production security truth.

## Views and semantics

| Widget | Metric | Source | Definition / caveat |
| --- | --- | --- | --- |
| Managed agents | Enrolled endpoints | `Store.Snapshot().Agents` | All lab enrolled agent records; not evidence of installation |
| Online / offline / unknown | Connectivity | Server-recorded `LastSeen` | Online if heartbeat age is <= 5 minutes; offline if later; unknown for missing/future timestamps. Reported client `Health` is not trusted for connectivity |
| Offline duration | Missed check-in | Server-recorded `LastSeen` | `max(0, now - LastSeen) / 86400` in days; unknown if no valid time, never claim a machine is compromised from absence |
| Daily alert trend | Rule signals grouped by UTC day | Correlated detections | Counts created from retained events only, using UTC calendar-day windows 1/7/30; detection != confirmed malware |
| Alerts by severity | Critical, high, medium, low, informational | Detection `Severity` | Explicit zero counts; no fake critical incidents from raw Sysmon events |
| Most active machines | Most collected events by endpoint | Raw events retained in selected window | Activity means event count, not CPU, network bandwidth, or maliciousness |
| Most triggered rules | Count of alerting rule matches | `Detection.RuleID` | Distinct from the number of deployed rules and from signature database entries. Currently only a Windows DLL-load heuristic rule exists |
| Applied policy coverage | Agent-acknowledged policy IDs | `Agent.AppliedPolicyID` | Not proof that Sysmon configuration was applied correctly or that rule execution is healthy |
| Scan jobs | Queued, leased, completed, failed/expired | ScanJob store | These are control-plane states; actual ClamAV execution requires a running Rust agent |
| Visibility gaps | Missing security signals | Explicit capability list | Show unsupported data as **Not instrumented**, never invent values |

Time range is limited to 1, 7 or 30 UTC calendar days. `GET /api/overview?days=7` requires the development bearer token and returns a structured JSON object from `BuildSOCOverview` with `generated_at`, `window_days`, `heartbeat_ttl_seconds`, `endpoints`, `inactive_machines`, `most_active`, `severity`, `alert_trend`, `top_rules`, `policy_coverage`, `scans`, and unavailable capabilities.

## UX acceptance (Agent 5 + QA)

- Cards for managed, online, offline, unknown, alerts, high/critical, retained events, failed scans.
- A click on a summary card opens its underlying agent, detection, event, or scan list; agent list has online/offline/unknown filter.
- Show top ten machines and triggered rules, sort descending and break ties deterministically.
- Show exact last seen local display time, elapsed inactivity in days if >= 24 hours, minutes otherwise, and unknown with no fake dates.
- Allow day window 1/7/30; daily trend explicitly says UTC. Empty values show zero or an empty-state explanation, not synthetic data.
- Include Security Visibility Gaps, scan failures and policy errors; avoid calling queued scans protection.
- Escape all user-originated identifiers/metadata in HTML. Keep keyboard navigation, focus outlines, semantic sections and reduced-motion support.
- The laboratory backend returns at most 2,000 retained events and uses an in-memory scan queue; no historical or multitenant claim is allowed.

## Future API requirements (Agent 2)

Before production, replace development shared token with RBAC + tenant filtering, device mTLS and durable PostgreSQL / telemetry storage. Expose server-side pagination, cursor-based alert searches, independent aggregate counters outside the retention ring, synchronized clock-skew checks, explicit time series completeness, and separate incident and response status. For agent liveness, use server-received heartbeat plus enrollment/certificate health and enrolled/uninstalled states. Do not reveal endpoints from another tenant.

## Additional Agent 1 security-health metrics

**Next priority, not yet implemented:** signature database freshness and failed update age; scanner worker up/down, last success and error; Sysmon ETW Event 7 coverage/loss and collector blind spots; policy desired/applied hash drift; tamper/uninstall-denial events; persistence and ingestion-lag/drop/backpressure; time to acknowledge/triage alerts, unreviewed criticals, alert suppression and false-positive feedback; protection-mode coverage by platform; quarantine failures and restores with audit trail. These must be measured from authenticated source telemetry, not guessed by the UI. Alert volume should be normalized for fleet size and collector coverage to avoid rewarding noisy rules.

## Kaspersky EDR public workflow reference (design input)

For the next TuranSec SOC iteration, use [our Kaspersky EDR benchmark and independent-design rules](kaspersky-edr-benchmark.md) for incident queue hierarchy, investigation pivots, configurable protection/updates/alert widgets, and operator task flows. Preserve original TuranSec code, layout, assets and accessible design. A workflow reference does **not** license proprietary Kaspersky implementation or claim those features already work. Priority remains authenticated endpoint scanning/telemetry and honest status reporting before visual polish.
