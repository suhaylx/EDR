# TuranSec EDR — Kaspersky EDR functional and SOC UX benchmark

**Decision:** 21 November 2026. **Status:** Product and interface requirements, not a claim of completed implementation.
**Owners:** Agent 5 Frontend/UX, Agent 1 InfoSec; Agent 2 owns API contracts, Agent 3 QA, Agent 4 PM coordination.
**Starting code:** dependent laboratory SOC dashboard pull request #8, based on the laboratory MVP #5.

## Reference policy

The owner requests **Kaspersky EDR Expert and Kaspersky Security Center Web Console as references for both security functions and operator interface design**. Use their *publicly documented workflows and common functional ideas* as a benchmark. Implement all TuranSec source code, visual components, icons, typography, layouts, copy, and interaction styling **independently**. Never assume a commercial vendor's source code, screenshots, icons, logos, fonts, bundled rules, proprietary signatures, or exact protected interface assets are reusable; reuse requires verified appropriate permission and license. Do not represent TuranSec as a Kaspersky product, partner, compatible client, or clone.

Continue using Apple Human Interface Guidelines only as an *additional principle-level* reference for clear hierarchy, feedback, keyboard and screen-reader accessibility, adaptive layouts, low cognitive load and native Windows/Linux behavior. TuranSec owns a distinctive visual identity.

### Public functional benchmarks (read-only research)

1. [Kaspersky Security Center — dashboard and widgets](https://support.kaspersky.com/ksc/14/en-US/166064.htm): interactive, customizable monitoring across protection, deployment, updates and threat statistics, with links to underlying details.
2. [Kaspersky Security Center — Web Console administration](https://support.kaspersky.com/ksc/14/en-US/166361.htm): managed devices, installed applications, policies, tasks, reports and operator controls.
3. [Kaspersky EDR Expert — incidents](https://support.kaspersky.com/KEDR_Expert/en-US/221314.htm): incident work queue, alert grouping, severity distinct from priority, assigned analyst, status and investigation.
4. [Kaspersky Security Center — threat alerts](https://support.kaspersky.com/ksc/14/en-US/215743.htm): alerts and filtering by date and detection attributes.

Do not infer from these references that a TuranSec feature or Kaspersky API integration exists.

## TuranSec navigation and workflows

| TuranSec module | Operator's question | MVP data contract | Acceptance / explicit gap |
| --- | --- | --- | --- |
| **SOC Overview** | Are my machines protected and reporting? What changed today? | `GET /api/overview?days=1|7|30` from PR #8 | Online/offline/unknown based on *server timestamp*, severity trend, top machines by event volume, actual rule hits, scan health, explicit telemetry gaps; fleet drill-down |
| **Alerts** | What detections need triage now? | Existing lab detections list and evidence IDs | Severity, confidence, engine, host, first/last seen, rule/version; filters; distinct from raw events; only mark a confirmed incident after analyst/rule decision |
| **Incidents** | What does an analyst own? | Future incident aggregate API | Status, severity, independent priority, assignee, evidence timeline, linked alerts and response history. Show **not available** until backend and RBAC exist |
| **Investigation** | Why did this DLL/process alert fire? | Future structured event/correlation graph | Explain Sysmon Event 11 *file creation* versus Event 7 *actual image loading*, linked Event 1 parent/process GUID; record hash/signer/correlation confidence; no claim of executed DLL from creation alone |
| **Threat hunting** | Can I search raw observations and pivots? | Future authorized event search with backend limits | Search by agent, hash, process, command line, user, network and time; stable tenant/RBAC scopes, paging, retention gaps |
| **Endpoints** | Which machine was last seen and what is degraded? | Agent heartbeat, OS, local scan/job state | Age since heartbeat in days, policy version, scan and Sysmon capability; inventory detail and audit history |
| **Rules & detection coverage** | Which rules actually triggered? Which policies are installed? | `overview.top_rules` plus future rule catalog | Keep **fired alert count** separate from installed/enabled rules and from signature database size; show rule ID/version, severity, confidence, false-positive/suppression state |
| **Scans & response** | Did the scan finish and was the action safe? | Existing lab scan jobs; future signed response commands | Queue/lease/completed/error distinct from actual scanner verdict; quarantine/restore and irreversible actions unavailable unless agent, policy and QA prove support |
| **Policies / Sysmon** | Is desired configuration really applied? | Existing lab policy records; future agent-acknowledged hashes | OS-specific capabilities, canary validation and rollback, signed desired vs effective policy; do not imply XML preview applied to device |
| **Reports & administration** | Are coverage and workflows auditably controlled? | Future durable backend with RBAC | Accessible reporting/exports, tenant isolation, signed administrative actions and audit logs |

### Original TuranSec visual direction

- **Information hierarchy:** dashboard summary → filterable investigation queue → evidence detail with timeline and provenance → authorized response confirmation. Build distinct components and proportions, not a pixel-matched Kaspersky console.
- **Layout:** crisp TuranSec wordmark and original device/alert iconography; a compact navigation rail, restrained data density, readable tabular numerals, generous focus targets; responsive panels for laptop SOC analysts.
- **Appearance:** TuranSec-original neutral dark/light surfaces, measured high-contrast accent for selection, semantic red/orange/blue severity tokens that also include text labels; never represent health using color alone.
- **Usefulness:** every KPI and chart segment must open a real filtered data view; no inert buttons posing as supported features. Refresh timestamp and coverage/retention limitations stay visible.
- **Accessibility:** full keyboard tab/escape behavior, visible focus, labels for icon controls, semantic table headers, reduced-motion preference, accessible name/value contrast, localization-ready date formatting; aim for WCAG 2.2 AA.
- **Trust:** unknown/offline/unsupported telemetry is not shown as green; a ClamAV `clean_by_signature` result is not proof of safety; an assigned rule is not a triggered alert; raw Sysmon events do not automatically become incidents.

## Work packages and QA gates (for the hourly sprint)

### UX-REF-01 — Agent 5: screen and interaction implementation

1. Extend PR #8 via a **separate dependent feature branch** with original TuranSec navigation and an `Alerts` queue drill-down, retaining the existing status dashboard.
2. Deliver `docs/ux/design-system.md` (original type/color/spacing/focus tokens and responsive breakpoints) and screen states for overview, endpoint detail, alert details, incident-not-available and policy status.
3. Wire only existing lab endpoints; mark missing backend functionality honestly. Avoid Kaspersky screenshots or copied vendor assets in code, artifacts or tests.
4. Acceptance: `node --check backend/web/app.js`; browser smoke of real endpoint filters and empty states; keyboard/focus/contrast test report. React/TypeScript migration is a distinct later deliverable unless proven.

### SEC-REF-01 — Agent 1: detection semantics

Define evidence-level rule firings, alert triage severity and false-positive/suppression controls, Win DLL load-vs-create distinction, ClamAV verdict/scan errors, coverage/missing-telemetry indicators. Identify when the analyst may escalate a detection to an incident.

### API-REF-01 — Agent 2: stable secure contract

Provide `/api/overview` schema/typed client contract, explicit filtered alert-detail query design and tenant-safe pagination plan. Keep the localhost shared token **lab-only**. Do not claim mTLS, durable event storage or RBAC until implemented and independently tested.

### QA-REF-01 — Agent 3: evidence-based validation

Cover offline age, future heartbeat, UTC 1/7/30-day windows, severity and rule counts from **detections not raw events**, empty fleet, XSS-safe fields, no cross-tenant claims, and proper disabled states for unimplemented backend features. Mark real endpoint/Windows/Linux acceptance **NOT RUN** until tested.

### PM-REF-01 — Agent 4: technical ownership and review

Cross-reference GitHub PRs #5 and #8 and the new review PR, keep precise technical tasks/acceptance checks on the activity board; no cosmetic hourly commits, unsafe auto-merges, or unsupported delivery claims. Favor the P0 real agent-to-Go auth/scan path over new presentation polish when security milestones are blocked.

## Release gate

This benchmark is a product decision; **not production-ready software**. A pilot requires a running, authenticated Rust endpoint, real ClamAV 1.5.5 scanning/updates and suitable Sysmon telemetry with QA evidence; dashboard styling alone does not satisfy it.
