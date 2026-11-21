# TuranSec EDR

**Status:** Pre-production engineering project. Not a production antivirus or endpoint detection and response product.

TuranSec EDR is an original Windows/Linux endpoint-security platform under development.

- **One managed endpoint agent**: Rust service/daemon orchestrating ClamAV signature scanning, static file analysis and Sysmon telemetry, with separately supervised vendor components and an optional non-privileged local UI.
- **Go backend**: authenticated API and future mTLS agent enrollment, durable events, central policy control and deployment coordination.
- **SOC dashboard**: current laboratory interface, with an original React + TypeScript design planned.
- **Enterprise roadmap**: tamper protection with scoped maintenance authorization, safe Sysmon policy rollout, AD/LDAPS discovery and approved Windows/Linux deployment, tenant isolation, QA release gates.

**Security notice:** The initial demo backend may use a development-only shared token, and must only run on localhost in an isolated lab. Do not expose it to production endpoints. No automatic malware execution, irreversible deletion, or unapproved remote deployment.

## Engineering roles

1. **InfoSec / Security Functionality** — owns malware-detection and response requirements, original detection rules, safe fixtures, security reviews.
2. **Backend & Deployment** — owns Go/Rust implementation, CI/CD, packaging, infrastructure, deployment and rollback.
3. **QA** — owns acceptance, negative/security testing, compatibility and release gates.
4. **PM** — owns prioritized technical assignments, reviews and evidence-based reports.
5. **Frontend/UX** — owns React SOC dashboard and local Windows/Linux UI; follows human-centered design principles adapted to the host OS.

Architecture and task backlog: [TuranSec EDR project specification](https://chatgpt.com/space/page_dec24f52e8a88191baead60bf5ef9a56).

## Local development

Initial proposed layout:
- `backend/`: Go API, tests, browser-based lab dashboard
- `agent/`: Rust agent scaffold
- `rules/`: original detection rules, deliberately low confidence until corroborated
- `config/sysmon/`: non-production, OS-specific Sysmon lab templates
- `docs/`: architecture, role assignments, security functionality, testing and lab runbook

**Do not treat README or documentation as a claim that the full EDR is implemented.**
