# One-file TuranSec endpoint installer (engineering pilot)

Build **one setup binary per OS** from the same source:
- Windows Server 2022 x64: `TuranSec-Agent-Setup.exe`.
- Ubuntu 24.04 x64: `TuranSec-Agent-Setup`.

The setup binary contains the native TuranSec Rust agent. Installation orchestrates
ClamAV via **approved Ubuntu packages** on Linux, and requires an existing
approved Windows ClamAV installation plus independently signed Microsoft Sysmon.
It **does not bundle vendor executables or auto-enroll endpoints**.

An organization must first issue and register the endpoint certificate.
For Windows, approve the TuranSec publisher thumbprint and Sysmon EULA.
Use an approved **127.0.0.1:9443** encrypted tunnel for the backend.

Linux example:
```bash
sudo ./TuranSec-Agent-Setup --identity-dir /approved/agent-pki \
  --tenant lab --agent-id linux01 --check-only
# Remove --check-only for an approved host installation.
# Add --activate only after ClamAV freshness, mTLS and host checks.
```

Windows PowerShell example:
```powershell
.\TuranSec-Agent-Setup.exe --identity-dir C:\Approved\AgentPKI `
  --tenant lab --agent-id windows01 --sysmon C:\Approved\Sysmon64.exe `
  --clamav-dir C:\Approved\ClamAV --agent-signer APPROVED_THUMBPRINT `
  --accept-sysmon-eula --check-only
```

**Current limitations:** Windows uses a bounded Scheduled Task, not an accepted
Windows service. Linux uses a systemd oneshot worker/timer, disabled until
explicit activation. Sysmon telemetry is not connected to the authenticated
SOC ingest pipeline. ClamAV signature freshness, signed Windows and Linux
installer packages, enterprise PKI/enrollment, installed-host rollback and
deployment owner approval remain independent gates. Native CI packaging and
negative-input tests do not close those gates.

## Generated 3-in-1 deployment ZIPs

The admin console builds a ZIP from three SHA-256-pinned approved components
plus an installation orchestrator; no endpoint private keys or CA secrets are
embedded. Windows runs `Install-TuranSec.ps1`, Linux runs `install-turansec.sh`.
An issuer-provided, already-enrolled endpoint identity remains a mandatory
precondition. Each launcher validates component checksums and fails closed
before installing missing/unapproved payloads. Windows additionally requires
an approved signer for the **outer** TuranSec setup executable and a valid
Microsoft Sysmon signature. Linux requires explicit Sysmon EULA approval.

These are **one-entrypoint provisioning workflows**, not yet fully automatic
enterprise EDR installers. Windows agent execution is a bounded task, Linux is
a systemd timer; Sysmon-to-SOC event ingestion, remote network tunneling,
production signing, installed-host rollback and false-positive monitoring
remain incomplete. See [the 3-in-1 deployment guide](THREE_IN_ONE_DEPLOYMENT.md).
