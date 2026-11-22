# TuranSec Windows -> Ubuntu live Sysmon lab quick start

**Historical development guide.** For the current PostgreSQL and mTLS dashboard and authenticated Windows or Linux agents, use the [installation manual](INSTALLATION.md). The older shared-token or port 8080 procedures below describe the separate development demonstration.

**Lab-only, unsigned portable EXE.** Not an EDR installer, Windows service, mTLS-authenticated agent, prevention engine or production telemetry pipeline.

## Prerequisites (after both test servers are rebuilt)

- Ubuntu Go lab backend running; lab bearer token available to administrator, not copied to source control.
- Sysmon installed separately on Windows Server 2022, using signed Microsoft Sysinternals software and a reviewed Sysmon Modular-style policy. The collector handles **configured IDs 1–29 and 255**. Not all events are produced or enabled by a particular installation.
- Download the NEW TuranSec-EDR-Lab-Windows-x64 ZIP from the successful GitHub Actions build of this PR (not the old PR #22 ZIP). Check its SHA256SUMS.
- No direct public HTTP access to API; run the SSH tunnel on Windows. Do not disable Defender, SmartScreen, or host protections merely to run an unsigned binary.

## 1. Check actual Sysmon source (Windows PowerShell)

~~~powershell
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational'
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'
  Id = 1,3,7,10,11,13,21,22,25,255
} -MaxEvents 10 | Select-Object TimeCreated, RecordId, Id
~~~

If the channel does not exist, install/enable signed Sysmon first. Missing IDs may simply reflect a disabled rule or no matching activity. Neither the agent nor its dashboard invents events to fill a gap.

## 2. Open encrypted tunnel FROM WINDOWS to Ubuntu

Windows PowerShell A (leave running):

~~~powershell
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:8080:127.0.0.1:8080 uz-user@YOUR-UBUNTU-BACKEND-HOST
~~~

This uses **Windows-local port 8080** for the Rust agent. The Go lab backend must bind **127.0.0.1:8080** and refuse public interfaces. For a busy port, instead use local 18081 and set the TURANSEC_DEV_API_PORT environment variable to 18081. The dashboard browser can use local 18080 in a separate tunnel.

Check in another Windows PowerShell:

~~~powershell
Invoke-RestMethod http://127.0.0.1:8080/api/health
~~~

Expected status=ok and mode=development. The EXE is hardcoded to loopback 127.0.0.1 and will not contact public API addresses.

## 3. Check in and transfer genuine configured Sysmon events

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

# Check-in and report up to 256 ascending, previously unacknowledged Sysmon records.
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

Refresh your **securely tunneled** SOC dashboard. Expected: Agents lists win-lab-01; Telemetry & triage includes source=sysmon, source_event_id=1 for your benign process creation, actual ProcessGuid/image and source_record_id (Windows EventRecordID). Other IDs appear only if Sysmon actually records them. No detection or infection is implied by a benign process event.

## Acceptance / limitations

- lab_heartbeat=sent means Go accepted a check-in; sysmon_events_sent=N counts the observed, configured Sysmon IDs 1–29/255 accepted by the development API.
- Checkpoint in %LOCALAPPDATA%\TuranSec\lab-sysmon-checkpoint-win-lab-01.txt stores last posted RecordID but **no token**. Resetting it intentionally for QA may duplicate records.
- This poller reads ordered pages of up to 64 records, at most 4 pages (256 records) per 60-second interval. A sustained higher event rate can cause **backlog or dropped events**; a log reset/overwrite can invalidate the RecordID checkpoint. It is not a lossless, gap-accounted collector. After log reset/overwrite, gaps can occur. If agent ID changes, it starts a new checkpoint.
- It never uploads command lines, usernames, raw XML, registry values or clipboard contents. It uploads only allowlisted metadata (e.g. network address, DNS query, registry object, DLL path), reported event ID/provider/channel, source EventRecordID and timestamp. Parent ProcessGuid is only sent for Event ID 1.

- Where available, Windows CIM LastBootUpTime yields a sender-reported **winboot:** marker only for records dated within the **current OS boot**. Historical records and missing CIM results have no boot marker, so the process/network correlation rule declines to link them. This is not cryptographic boot attestation.
- **All telemetry remains unauthenticated sender claims behind a shared development token.** The mTLS production enrollment branches are separate, and no detection here proves an attack.
- Go lab server stores records in memory and uses a shared bearer token. No device mTLS, integrity attestation, or production enrollment. No Windows service is installed.
- Rollback: Ctrl+C agent console, clear token environment variable, close SSH tunnel. The EXE installs no service.
- Code QA is Rust tests plus Windows CI. The actual end-to-end pass still requires **real Windows Server and Ubuntu evidence**, not merely CI success.
