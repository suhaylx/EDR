# TuranSec 3-in-1 endpoint deployment (engineering pilot)

**Exactly three required endpoint components**, one verified installation
entry point per OS:

| Platform | Required components | One installation entry point |
|---|---|---|
| Windows x64 | TuranSec native agent + ClamAV + Microsoft Sysmon | `Install-TuranSec.ps1` |
| Ubuntu 24.04 x64 | TuranSec native agent + ClamAV + Sysmon for Linux | `install-turansec.sh` |

The **Admin → Agent packages** page can generate a per-endpoint ZIP when the
organization's approved payloads and `approved.json` SHA-256 manifest are
staged on the **dashboard host**. A SHA-256 value stored next to a binary does
not, by itself, prove a publisher's identity: verify supplier releases and
record the approved hashes **outside** the bundle before staging. Windows
TuranSec setup must be Authenticode-signed by your approved certificate;
Sysmon must have a valid Microsoft signature. ClamAV vendor package release
signatures and Microsoft Linux package origin must also be reviewed.

The bundle contains **no agent private keys**. Your issuer must separately
create and register an identity and securely place `server-ca.pem`,
`agent.pem`, and `agent.key` on the destination. The server at
`127.0.0.1:9443` requires an approved encrypted tunnel on a remote endpoint.
**Do not expose 9443, 9444, 9445 or ClamAV 3310 to untrusted networks.**

## Windows

Extract the ZIP to an administrator-controlled directory and run in an
elevated PowerShell console:

```powershell
powershell.exe -NoProfile -File .\Install-TuranSec.ps1 `
  -IdentityDir C:\Issued\EndpointPKI `
  -ApprovedAgentSigner YOUR_APPROVED_CERT_THUMBPRINT `
  -AcceptSysmonEula -CheckOnly
```

Remove `-CheckOnly` to provision the three components, and optionally add
`-Activate` only after an approved pilot readiness check. The launcher
checks the approved hash of every file, verifies both vendor code signatures,
runs the TuranSec enrollment preflight, extracts the pinned official ClamAV
ZIP, obtains ClamAV signatures, installs a loopback-only `clamd` service,
then installs Sysmon and the TuranSec bounded scheduled task if requested.

**Windows limitations:** vendor installer signatures are required; no
approved signing certificate is shipped. Internet access may be needed to
update ClamAV signatures, the service must start successfully, and the agent
does not yet run as a dedicated Windows endpoint service. There is no
cryptographic proof of telemetry coverage or installed-host rollback.

## Ubuntu 24.04

After extracting the ZIP and securing the separately issued identity:

```bash
sudo bash ./install-turansec.sh --identity-dir /etc/issued-agent \
  --accept-sysmon-eula --check-only
# If preflight passes, remove --check-only for package installation.
# Explicitly add --activate only after mTLS and scanner verification.
```

The launcher checks all three hashes and the expected enrollment, installs
the approved compatible ClamAV/Sysmon .deb packages, explicitly initializes
Sysmon, and deploys the Rust agent with a bounded systemd timer.
The packages must be appropriate for Ubuntu 24.04, including dependencies.
The default local-lab protocol still requires a protected 127.0.0.1 tunnel.

## Release gates: not completed

- Full installed-host **Windows/Ubuntu** end-to-end QA, recovery and rollback
- Centralized Sysmon/ClamAV/behavior event ingestion and timeline search
- Production endpoint onboarding, PKI rotation/revocation and device identity
- Persistent Windows service and signed, versioned release distributions
- Real-time behavior detection, containment/isolation, quarantine and response
- SOC-scale tenant policies, detection performance and HA/load testing

Until these are demonstrated against real enrolled endpoints, label this
**engineering pilot**, not a Kaspersky-equivalent or production protection
platform.
