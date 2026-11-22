# TuranSec EDR: Windows Server 2022 test-agent installation and lab validation

**Historical development guide.** For the current PostgreSQL and mTLS dashboard and authenticated Windows or Linux agents, use the [installation manual](INSTALLATION.md). The older shared-token or port 8080 procedures below describe the separate development demonstration.

**Status:** laboratory smoke test only, **NOT** an installed EDR Windows background service, complete Sysmon collector, production AV, or automatic quarantine. Updated 2026-11-21.

**Topology:** one dedicated/disposable Windows Server 2022 endpoint and Ubuntu 24.04 backend. **Windows repo branch:** `feat/windows-server-2022-lab-preflight-20261121` (draft PR #18, based on Rust worker PR #16). Ubuntu SOC graph/dashboard is on **different** draft branch `feat/process-incident-graph-20261121` (PR #13). Do not assume these feature branches were merged into `main`.

## Mandatory security safeguards

- **Rotate** administrator or Linux passwords previously shared through chats; never copy credentials or API tokens into issues, Markdown, Git or screenshots.
- Do not use a production domain controller, real users' sensitive files, or a business Windows Server as the test target. Snapshot the VM first. Obtain approval for all changes and use RDP only via VPN or trusted admin IP, ideally with NLA/MFA.
- Do not disable Microsoft Defender, Defender Antivirus real-time protection, EDR or other controls to make a test pass. Antivirus co-existence must be separately evaluated. Do not execute real malware or upload unknown samples; use benign process activity and the official EICAR test file only in an isolated lab.
- Do **not** open ClamAV TCP 3310 to any network source. `clamd`'s protocol is not authenticated; bind it to **127.0.0.1 only**.
- Do **not** send the development bearer token to the Ubuntu backend over public plain HTTP. Use the outbound SSH tunnel in section 5. Go may listen on Ubuntu `0.0.0.0:8080` as requested, but provider/UFW firewall rules must deny public inbound 8080.

## 1. Verify host and preparation

Open a trusted PowerShell session as administrator on the dedicated test machine and verify:

```powershell
(Get-CimInstance Win32_OperatingSystem) | Select-Object Caption,Version,BuildNumber
(Get-CimInstance Win32_ComputerSystem) | Select-Object TotalPhysicalMemory
Get-Volume -DriveLetter C | Select-Object DriveLetter,SizeRemaining
Get-Command git,ssh,cargo -ErrorAction SilentlyContinue
```

Windows Server 2022 normally reports build `20348`. Aim for **4 vCPU, 8 GiB RAM and 80 GiB disk** as an initial lab estimate, including at least 20 GiB free. Ensure Windows Update and Defender health are documented; protect RDP at the cloud and Windows firewall layers. Take a recoverable VM snapshot before Sysmon/ClamAV installation.

Create a staging directory:

```powershell
New-Item -ItemType Directory -Force C:\TuranSecLab | Out-Null
```

Install the OpenSSH Client if `ssh -V` fails (only on supported Windows image):

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
```

## 2. Retrieve and test the actual Rust worker branch

Use Git for Windows and a **read-only** private-repository SSH key. Verify GitHub's published host fingerprint before first SSH trust:
https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints

```powershell
git clone --branch feat/windows-server-2022-lab-preflight-20261121 `
  git@github.com:suhaylx/EDR.git C:\TuranSecLab\EDR

cd C:\TuranSecLab\EDR
powershell.exe -NoProfile -File .\scripts\windows-lab-preflight.ps1
```

The repository's **read-only preflight** checks OS, memory/disk, Sysmon Event 1 visibility, local ClamAV port 3310, `cargo`, `ssh`, and API tunnel health; it does not install or change settings. Review the source before executing any script. If local execution policy blocks it, work with your system administrator rather than disabling policy globally.

Install Rust using the official https://rustup.rs/ installer with a supported `x86_64-pc-windows-msvc` toolchain. Install Microsoft's Visual Studio **Build Tools with Desktop development with C++ / MSVC linker and Windows SDK** as required for compilation. Open a *new* shell and verify:

```powershell
rustc --version
cargo --version
cd C:\TuranSecLab\EDR\agent
cargo test
cargo build
```

`cargo test` tests the Rust protocol client and stubs; it does **not** prove live ClamAV, EICAR, Sysmon subscription or Windows service stability. The current executable is a **one-shot CLI**; **do not register it as a production Windows service**.

## 3. Install and verify Microsoft Sysmon

Download Sysmon from the **official Microsoft Sysinternals page**:
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

Extract the signed `Sysmon64.exe` to `C:\TuranSecLab\Tools\Sysmon64.exe` (create the folder as needed), and verify the file's Authenticode signer/status:

```powershell
Get-AuthenticodeSignature C:\TuranSecLab\Tools\Sysmon64.exe |
  Select-Object Status,SignerCertificate
```

Only after validating the signature and confirming this is a disposable lab endpoint, install a minimal/default Sysmon configuration:

```powershell
& C:\TuranSecLab\Tools\Sysmon64.exe -accepteula -i
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational'
Start-Process "$env:WINDIR\System32\cmd.exe" -ArgumentList '/c exit 0' -Wait
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'
  Id = 1
} -MaxEvents 3 | Select-Object TimeCreated,Id,RecordId
```

Record genuine **Event ID 1** as proof of local process creation only. Installing Sysmon does **not** mean TuranSec automatically reads or uploads those events; the Rust Sysmon collector is still a placeholder. Do not enable broad high-volume Event 7 DLL logging without a tested policy, storage budget and rollback plan. For later production telemetry config see `docs/security/sysmon-multisignal-coverage.md` on the relevant feature branch.

## 4. Install and verify ClamAV on the Windows endpoint

Download a supported Windows x64 ClamAV build from **https://www.clamav.net/downloads** and follow official setup instructions at https://docs.clamav.net/manual/Installing.html. Verify its signature/source, supported platform and version; **ClamAV 1.5.5** is the planned integration target subject to host compatibility validation. Windows Server 2022 support must be established in this lab, not assumed.

Configure `freshclam` to retrieve **official signature databases** with appropriate filesystem permissions. In the local `clamd.conf` (use the file location documented by the installed ClamAV build), configure at least:

```ini
TCPSocket 3310
TCPAddr 127.0.0.1
```

Remove/comment any sample `Example` directive and configure the installation's actual database/log paths and resource limits. Use the official `clamd` instructions to start it; this manual does not assume the package installed or registered a Windows service. Never bind `clamd` to `0.0.0.0`. Verify:

```powershell
Test-NetConnection 127.0.0.1 -Port 3310
Get-NetTCPConnection -LocalPort 3310 -State Listen -ErrorAction SilentlyContinue |
  Select-Object LocalAddress,LocalPort,State,OwningProcess
```

**Required:** listener `127.0.0.1`, not `0.0.0.0`. A TCP listener only proves that a port is reachable; it **does not** verify scanner signatures or database freshness. Record the real `clamd` version, `freshclam` update success and database version using installed-vendor tools/logs.

For an approved real detection test, download the **official EICAR test file** from https://www.eicar.org/download-anti-malware-testfile/ in the isolated lab. Another resident AV may intercept it first: record which product detected the file and **do not disable** security tools to force ClamAV attribution. Do not test live malware.

## 5. Make the Windows-local API endpoint via encrypted SSH tunnel

The Rust lab worker **only calls `http://127.0.0.1:8080`**, and has no production TLS or remote-device enrollment. **Do not** change it to contact the Ubuntu public IP directly over plaintext HTTP. Complete the Ubuntu dashboard setup first: [Ubuntu 24.04 lab manual](LAB_UBUNTU_2404_DASHBOARD_INSTALL.md), including **blocking public inbound TCP 8080** before binding Go to `0.0.0.0`.

On Windows, verify that Ubuntu SSH is accessible and the host fingerprint is trusted:

```powershell
Test-NetConnection LINUX_SSH_HOST -Port 22
```

Create an **outbound** SSH port-forward from Windows to Ubuntu, replacing only your private SSH username/host placeholders:

```powershell
ssh -o ExitOnForwardFailure=yes -N `
  -L 127.0.0.1:8080:127.0.0.1:8080 `
  -L 127.0.0.1:18080:127.0.0.1:8080 `
  LINUX_SSH_USER@LINUX_SSH_HOST
```

Keep this window running. In a **different** Windows PowerShell window:

```powershell
Invoke-RestMethod http://127.0.0.1:8080/api/health
```

Expected JSON includes `status: ok`, `mode: development`. If port 8080 is already occupied on Windows, stop the conflicting local application in the isolated lab or forward another Windows-local port and set `TURANSEC_DEV_API_PORT` accordingly; the read-only preflight probes 8080 only. Open the dashboard at **http://127.0.0.1:18080/** in the Windows browser through the tunnel.

## 6. Register the test agent and run a **benign** end-to-end scan job

Obtain the freshly generated `EDR_DEV_TOKEN` on the Ubuntu host through a trusted channel; **do not** put it in Git, chat, issues, scripts or screenshots. In the *second* Windows PowerShell window, enter it with an interactive prompt so it is not placed in shell history:

```powershell
$secure = Read-Host 'Lab API token' -AsSecureString
$env:EDR_DEV_TOKEN = [System.Net.NetworkCredential]::new('', $secure).Password
Remove-Variable secure
$env:TURANSEC_LAB_SCAN_ROOT = 'C:\TuranSecLab\scan'

New-Item -ItemType Directory -Force C:\TuranSecLab\scan | Out-Null
Set-Content -NoNewline C:\TuranSecLab\scan\benign.txt 'TuranSec benign test'
$headers = @{ Authorization = "Bearer $env:EDR_DEV_TOKEN" }
```

Register the endpoint **in the lab backend only**:

```powershell
$agentBody = @{
  id = 'win-srv22-lab'
  platform = 'windows'
  group = 'lab'
} | ConvertTo-Json
Invoke-RestMethod -Method Post `
  -Uri 'http://127.0.0.1:8080/api/agents' `
  -Headers $headers -ContentType 'application/json' -Body $agentBody
```

Queue one explicitly allowed **local path** scan:

```powershell
$jobBody = @{
  agent_id = 'win-srv22-lab'
  request_id = 'first-benign-test-001'
  scan_type = 'path'
  path = 'C:\TuranSecLab\scan\benign.txt'
} | ConvertTo-Json
Invoke-RestMethod -Method Post `
  -Uri 'http://127.0.0.1:8080/api/scan-jobs' `
  -Headers $headers -ContentType 'application/json' -Body $jobBody
```

Run the one-shot Rust scan worker, which leases a maximum of **one** job and streams a bounded regular file to the loopback ClamAV daemon:

```powershell
cd C:\TuranSecLab\EDR\agent
cargo run -- --lease-and-scan win-srv22-lab

Invoke-RestMethod -Uri 'http://127.0.0.1:8080/api/scan-jobs' -Headers $headers
```

Expected **only when real `clamd` with valid signatures is running**: job status `completed` with verdict `clean_by_signature` for the benign file; `clean_by_signature` is **not proof the file is harmless**. If ClamAV is down or returns an error, job should record `failed`/`error`; the worker must not fabricate a success. Quick and full scans intentionally report `unscanned` because those profiles have not been implemented. Do not run jobs on confidential/production files.

When finished, clean the token from the current PowerShell process:

```powershell
Remove-Item Env:EDR_DEV_TOKEN -ErrorAction SilentlyContinue
Remove-Item Env:TURANSEC_LAB_SCAN_ROOT -ErrorAction SilentlyContinue
```

## 7. Repeat the read-only QA preflight and log actual evidence

```powershell
cd C:\TuranSecLab\EDR
powershell.exe -NoProfile -File .\scripts\windows-lab-preflight.ps1
# Optionally use -Json for structured QA output; review before sharing.
```

| Acceptance check | Evidence needed |
| --- | --- |
| Windows Server 2022 compatibility | Actual build/version, `cargo test`, available disk/RAM |
| Sysmon collection | **Observed** Event 1 ID/time/source, not a synthetic dashboard event |
| ClamAV health | Actual engine + signature DB versions; local `127.0.0.1:3310`; safe EICAR attribution |
| Backend tunnel | Windows loopback HTTP 200 on `/api/health` through SSH |
| Job integration | Create → lease → ClamAV response → completion or explicit failure shown in Go API |
| Dashboard | Windows local browser renders, no token over public HTTP |
| Negative cases | Missing clamd, nonexistent path, symlink escape, expired lease, agent mismatch, no unauthorized delete |

**Keep PASS / FAIL / NOT RUN distinct.** A successful `cargo test` with simulated ClamAV replies does not constitute a live signature engine test. This CLI does not start continuous antivirus monitoring, implement tamper defense, or collect genuine Sysmon telemetry into the backend. For enterprise release, mTLS device/tenant identity, a durable result queue, signed command authorization, service packaging, safe file-descriptor opening and Windows/Linux canary QA are required.

## Help / recovery

- **SSH/health fails:** verify Ubuntu `ssh` service, SSH host-key, provider security rules, Windows outbound TCP 22, Go service active, and both sides of the port-forward. Do **not** open Ubuntu HTTP 8080 to the public internet.
- **Sysmon event absent:** verify the service and Operational event channel. A Sysmon installation alone isn't a TuranSec collector.
- **`cargo test` fails:** inspect MSVC Build Tools, Windows SDK, Rust target and current branch, report exact first error without secrets.
- **ClamAV port open but errors:** verify real `freshclam` update, database paths, vendor logs and scanner configuration; port reachability is not scanner health.
- **PR #18 is documentation/preflight only:** do not claim the Rust worker automatically runs at boot or is an installed signed Windows security service.
