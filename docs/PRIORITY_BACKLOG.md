# TuranSec EDR - Prioritized Delivery Backlog

Baseline: 2026-11-21. Evidence: local lab starter; these entries are planned,
not shipped. Project Manager owns prioritization; agents own implementation
and signoff. Change status only with a commit/PR, test and target evidence.

| ID | Priority | Owner | Task | Dependency / acceptance gate | Status |
| --- | --- | --- | --- | --- | --- |
| SEC-001 | P0 | Agent 1 | Agent/control-plane threat model, certificates, signed command policy, tenant boundary | Document reviewed misuse/replay and cross-tenant cases | Planned |
| BE-001 | P0 | Agent 2 | mTLS device enrollment + per-device identity and scoped API auth | SEC-001; unit/integration auth tests, no dev bearer token in production | Planned |
| BE-002 | P0 | Agent 2 | PostgreSQL persistence, schema migrations, durable event queue and audit | DB backup/restart/replay tests, schema provenance | Planned |
| DEVOPS-001 | P0 | Agent 2 | Private repository, CI, branch protection and documented release workflow | Owner/private-repo access, CI green, no secrets | Blocked: repository not yet identified |
| QA-001 | P0 | Agent 3 | Automated backend, agent and deployment acceptance matrix | Evidence for access abuse, failure, restart and rollback | Planned |
| AG-001 | P1 | Agent 2 | Rust agent heartbeats, durable offline queue, secure API integration | BE-001/002, QA fixtures for Windows/Linux | Planned |
| AV-001 | P1 | Agents 1 + 2 | ClamAV official signature scanning and safe update management | AV QA incl. EICAR and limits; bounded scanning | Planned |
| DFIR-001 | P1 | Agents 1 + 2 | Static PE/DLL/ELF inspection, hash, signer and metadata | Never execute unknown sample; test malformed files | Planned |
| SYS-001 | P1 | Agents 1 + 2 | Windows Sysmon process/file/load events and Linux capability-aware events | DLL load != file create; persist bookmarks | Planned |
| SYS-002 | P1 | Agent 2 | Dashboard Sysmon policy versions, targeting and safe apply/rollback | Independent worker, canary, QA regression and event-loss reporting | Planned |
| AD-001 | P2 | Agent 2 | Secure LDAPS discovery and signed MSI/GPO deployment plans | PKI validation, delegated permissions, owner approval | Planned |
| UI-001 | P2 | Agent 2 | React + TypeScript dashboard with SOC/endpoint/AV controls | Backend RBAC, data integrity and QA accessibility | Planned |
| TAMPER-001 | P2 | Agents 1 + 2 | Managed maintenance authorization and local tamper protection | Threat model, OS limits, emergency recovery, QA gates | Planned |

## First work cycle (next engineering day)

- Agent 1: review enrollment trust boundaries and command authorization,
  then produce a testable threat-model checklist for SEC-001.
- Agent 2: implement the next secure backend work increment; set up private
  repository and CI once the intended destination is available; verify Go
  tests and capture exact commit/PR evidence. Do not deploy to real hosts.
- Agent 3: define and run negative authentication/integrity tests and design
  a Windows/Linux agent and Sysmon test matrix.
- Agent 4: verify artifacts, ensure each task has owner/test/dependency,
  update this backlog, and publish the PM-led four-role daily status.

## Release gates

No production deployment until all applicable gates have evidence: InfoSec
approval, QA passed on specified Windows/Linux versions, signed artifacts,
RBAC/mTLS and tenant isolation, rollback exercise, persistent audit and
service health. Prefer reversible staged changes and stop on test failures.
