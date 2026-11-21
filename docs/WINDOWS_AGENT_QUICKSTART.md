# TuranSec Windows Server 2022 — quick start (LAB ONLY)

This portable `TuranSec-EDR-Lab-Agent.exe` is **not an installer** and **not a Windows service**. It does not currently collect Sysmon events, run continuously, provide active protection, or automatically enroll the device. It can run a basic CLI smoke test and request **one** existing scan job from the development Go API when configured. A genuine ClamAV scan requires a separately installed and working `clamd` bound to local `127.0.0.1:3310`.

## Install / run (PowerShell on the isolated Windows test VM)

1. In GitHub PR **#22**, open the successful `windows-lab-agent-build` Actions run; download the **TuranSec-EDR-Lab-Windows-x64** artifact ZIP and extract into `C:\TuranSecLab`. This ZIP contains the EXE, `README.md`, and `SHA256SUMS.txt`. Use only builds from your authorized private GitHub repository. **Do not bypass Windows Defender, SmartScreen, or enterprise execution policy.** The binary is currently unsigned.
2. Confirm the file is intact and launch a harmless smoke test:

```powershell
cd C:\TuranSecLab
Get-FileHash .\TuranSec-EDR-Lab-Agent.exe -Algorithm SHA256
Get-Content .\SHA256SUMS.txt
.\TuranSec-EDR-Lab-Agent.exe
```

The SHA-256 from `Get-FileHash` must match the first value in `SHA256SUMS.txt`. The smoke test should print `background protection is NOT active` and `sysmon_collector_not_implemented` and exit. It **does not create an agent in the SOC**.

## Optional: real ClamAV scan of a benign local test file

Only after separately installing and verifying genuine ClamAV with a current signature DB and `clamd` listening on **127.0.0.1:3310**:

```powershell
New-Item -ItemType Directory -Force C:\TuranSecLab\Samples | Out-Null
Set-Content -Path C:\TuranSecLab\Samples\hello.txt -Value 'hello lab'
Test-NetConnection 127.0.0.1 -Port 3310
.\TuranSec-EDR-Lab-Agent.exe --scan-file C:\TuranSecLab\Samples\hello.txt
```

No ClamAV daemon = scan error; that is an expected missing dependency, not a successful scan. Never open TCP 3310 externally.

## Optional: one scan job from the Linux lab API

This is **not persistent monitoring**. It requires (a) an agent ID already registered in the Go lab API, (b) an existing queued scan job for that ID, (c) a locally running ClamAV daemon, and (d) an SSH tunnel to the Ubuntu backend. Keep the private token out of shell history and screenshots.

In PowerShell window **A**, on the Windows machine:

```powershell
ssh -N -L 127.0.0.1:8080:127.0.0.1:8080 uz-user@89.126.221.102
```

In PowerShell window **B**, on the **same Windows machine**:

```powershell
cd C:\TuranSecLab
New-Item -ItemType Directory -Force C:\TuranSecLab\Samples | Out-Null
$env:TURANSEC_LAB_SCAN_ROOT = 'C:\TuranSecLab\Samples'
$env:EDR_DEV_TOKEN = Read-Host 'Development API token (do not share)'
.\TuranSec-EDR-Lab-Agent.exe --lease-and-scan win-lab-01
Remove-Item Env:\EDR_DEV_TOKEN
```

Use the exact ID of the already enrolled lab agent instead of `win-lab-01`. Only `path` scan jobs actually scan a file; `quick` and `full` report `unscanned` until those profiles are implemented. For all setup details see `docs/LAB_WINDOWS_SERVER_2022_AGENT_INSTALL.md` in the documentation PR #20.

**Verification:** Windows GitHub Actions unit tests + executable smoke test prove the binary builds and runs on Windows Server 2022. They do **not** prove Sysmon collection, real ClamAV signatures, mTLS device identity, installed service, or EDR efficacy. This is a private development-lab tool. No production deployment.
