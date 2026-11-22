# TuranSec EDR production acceptance gates

This repository's current Docker SOC and 3-in-1 endpoint bundles are **pilots**.
A release must satisfy every gate below with retained signed evidence, per OS.

| Gate | Required evidence | Current state |
|---|---|---|
| SOC authentication/RBAC | Password login security, CSRF, rate limits, protected mTLS upstream, role isolation | Implemented for lab; full enterprise IdP integration pending |
| Core SOC workflows | Real endpoint inventory, alert triage, case activity, bounded scan dispatch and receipts | Implemented subset; no raw telemetry hunt or process ancestry |
| Endpoint 3-in-1 | One trusted installer provisions Rust agent, ClamAV and Sysmon with signatures | Bundled pilot script; vendor approval and installed-host QA pending |
| Enrollment | Unique enrolled device identity, safe key storage, revocation and rotation | Issuer-controlled manual enrollment; automated secure enrollment pending |
| Windows service | Native service recovery, updates, signed MSI/EXE, rollback | Not implemented; scheduled task only |
| Event ingestion | Windows Sysmon and Linux Sysmon events delivered with source integrity | Not integrated into central operator SOC pipeline |
| Detection | Static malware signature, behavior rules, threat intel and provenance | Signature scans and basic events only |
| Response | Authorized quarantine/restore, process termination, network isolation | Not supported end-to-end; never simulate as successful |
| Reliability | Soak, startup, OS upgrades, disconnected/low-resource hosts, live EICAR evaluation | Installed-host sign-off pending |
| Security review | Threat model, cert issuance/expiry, audit/secret handling, supply-chain signing | Lab safeguards only; final reviews pending |

Release criteria: signatures approved, platform tests pass, rollback rehearsed,
security reviewers sign off on each permission boundary, and incident replay
demonstrates correct alert-to-evidence-to-response correlation. CI can gate
syntax/integration, but **cannot substitute** for tested endpoint protection.
