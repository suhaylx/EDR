# TuranSec Windows -> Ubuntu live Sysmon lab quick start

**Lab-only, unsigned portable EXE.** Not an EDR installer, Windows service, mTLS-authenticated agent, prevention engine or production telemetry pipeline.

## Prerequisites (after both test servers are rebuilt)

- Ubuntu Go lab backend running; lab bearer token available to administrator, not copied to source control.
- Sysmon installed separately on Windows Server 2022, using signed Microsoft Sysinternals software and an authorized XML configuration including **Event ID 1 / Process Create**.
- Download the NEW TuranSec-EDR-Lab-Windows-x64 ZIP from the successful GitHub Actions build of this PR (not the old PR #22 ZIP). Check its SHA256SUMS.
- No direct public HTTP access to API; run the SSH tunnel on Windows. Do not disable Defender, SmartScreen, or host protections merely to run an unsigned binary.

## 1. Check actual Sysmon source (Windows PowerShell)

~~~powershell
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational'
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'
  Id = 1
} -MaxEvents 2 | Select-Object TimeCreated, RecordId, Id
~~~

If the channel does not exist or lacks Event ID 1, install/enable Sysmon first. No simulated events are sent when the channel is missing.

## 2. Open encrypted tunnel FROM WINDOWS to Ubuntu

Windows PowerShell A (leave running):

~~~powershell
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:8080:127.0.0.1:8080 uz-user@89.126.221.102
~~~

This uses **Windows-local port 8080** for the Rust agent. For a busy port, instead use local 18081 and set the TURANSEC_DEV_API_PORT environment variable to 18081. The dashboard browser can use local 18080 in a separate tunnel.

Check in another Windows PowerShell:

~~~powershell
Invoke-RestMethod http://127.0.0.1:8080/api/health
~~~

Expected status=ok and mode=development. The EXE is hardcoded to loopback 127.0.0.1 and will not contact public API addresses.

## 3. Check in and transfer genuine process events

Windows PowerShell B, after extracting the NEW ZIP to C:\TuranSecLab:

~~~powershell
cd C:\TuranSecLab

# Read token securely without echoing typed characters.
$secureToken = Read-Host 'EDR development token' -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
try {
    $env:EDR_DEV_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
}
Remove-Variable secureToken -ErrorAction SilentlyContinue

# Check-in and report newest non-duplicate Sysmon process-create records.
.\TuranSec-EDR-Lab-Agent.exe --telemetry-once win-lab-01

# Continuous lab poll and heartbeat every 60 seconds (Ctrl+C to stop).
.\TuranSec-EDR-Lab-Agent.exe --telemetry-loop win-lab-01

# After Ctrl+C:
Remove-Item Env:\EDR_DEV_TOKEN -ErrorAction SilentlyContinue
~~~

In another PowerShell, execute this benign command while the loop is running:

~~~powershell
cmd.exe /c ver
~~~

Refresh your **securely tunneled** SOC dashboard. Expected: Agents lists win-lab-01; Telemetry & triage includes source=sysmon, type=process_create, actual process GUID/image and Windows EventRecordID in detail. No detection or infection is implied by a benign process event.

## Acceptance / limitations

- lab_heartbeat=sent means Go accepted a check-in; sysmon_process_events_sent=N counts real Sysmon Event ID 1 observations accepted by the API.
- Checkpoint in %LOCALAPPDATA%\TuranSec\lab-sysmon-checkpoint-win-lab-01.txt stores last posted RecordID but **no token**. Resetting it intentionally for QA may duplicate records.
- This poller takes at most the last 32 Sysmon Event ID 1 records every 60 seconds and **can miss events during high-volume periods**. It is not a lossless collector. After log reset/overwrite, gaps can occur. If agent ID changes, it starts a new checkpoint.
- It never uploads command lines or usernames: only event time, image, process GUID, parent GUID and source RecordID.
- Go lab server stores records in memory and uses a shared bearer token. No device mTLS, integrity attestation, or production enrollment. No Windows service is installed.
- Rollback: Ctrl+C agent console, clear token environment variable, close SSH tunnel. The EXE installs no service.
- Code QA is Rust tests plus Windows CI. The actual end-to-end pass still requires **real Windows Server and Ubuntu evidence**, not merely CI success.
