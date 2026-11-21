# TuranSec EDR — Initial priority backlog

**Status: assigned, not implemented.** Verify changes using code, tests, CI and PR evidence. Canonical architecture: https://chatgpt.com/space/page_dec24f52e8a88191baead60bf5ef9a56

| ID | Priority | Owner | Deliverable | Acceptance |
| --- | --- | --- | --- | --- |
| SEC-001 | P0 | InfoSec (Agent 1) | `docs/security/agent-enrollment-threat-model.md` and security-function spec for unified Rust/ClamAV/Sysmon agent | Threats include device identity, mTLS, tenant scope, replay, offline, cross-component failures; specific security gates |
| BE-001 | P0 | Backend/Deployment (Agent 2) | Go mTLS enrollment/device identity API with PostgreSQL schema, migration, tests | Cross-tenant and revoked/expired/replay cases reject; restart persists device identity; CI passes |
| QA-001 | P0 | QA (Agent 3) | `docs/qa/p0-test-matrix.md` plus executable API negative tests where code exists | Every scenario has expected/observed result, pass/fail/not-run, and release blocker classification |
| UX-001 | P1 | Frontend/UX (Agent 5) | `docs/ux/design-system.md` and React dashboard/local agent status/scan screens | Accessible keyboard/contrast, clear configured vs active states, no privileged GUI policy bypass |
| SEC-002 | P1 | InfoSec (Agent 1) | Original `rules/windows/dll-sideloading.yaml` and safe fixtures | Distinguishes file create Event 11 from real module load Event 7; documents false positives and coverage |
| BE-002 | P1 | Backend/Deployment (Agent 2) | One Windows/Linux TuranSec Rust agent supervising ClamAV and Sysmon | Single identity, policy, packaging; worker fault does not stop core; tested on both OSes |

The initial intended repository is **private** `suhaylx/EDR`. Do not push to unrelated repositories. Security and QA release gates must be satisfied before deployment.
