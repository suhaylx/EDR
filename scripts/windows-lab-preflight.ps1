#requires -Version 5.1
<#
.SYNOPSIS
  Read-only TuranSec EDR Windows Server 2022 laboratory readiness check.
.DESCRIPTION
  Collects only local configuration/availability evidence. It does not install
  Sysmon, ClamAV, Rust, agents, adjust firewall, contact external hosts, or read
  administrator passwords/API tokens. The development API check is loopback-only.
#>
[CmdletBinding()]
param(
    [switch]$Json,
    [switch]$RequireReady
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$checks = New-Object 'System.Collections.Generic.List[object]'

function Add-Check {
    param([string]$Name, [string]$Status, [string]$Detail)
    $script:checks.Add([pscustomobject]@{
        name = $Name
        status = $Status
        detail = $Detail
    })
}

function Test-LoopbackPort {
    param([int]$Port)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $pending = $client.BeginConnect([System.Net.IPAddress]::Loopback, $Port, $null, $null)
        if (-not $pending.AsyncWaitHandle.WaitOne(800)) { return $false }
        $client.EndConnect($pending)
        return $true
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

$osCaption = 'not available'
$osBuild = 'not available'
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $osCaption = [string]$os.Caption
    $osBuild = [string]$os.BuildNumber
    if ($osCaption -match 'Windows Server 2022' -and $osBuild -eq '20348') {
        Add-Check 'os' 'PASS' "${osCaption} (build ${osBuild})"
    } else {
        Add-Check 'os' 'WARN' "Expected Windows Server 2022 build 20348; found ${osCaption} (${osBuild})"
    }
} catch {
    Add-Check 'os' 'WARN' 'Could not read Windows operating system version'
}

try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $memoryGiB = [math]::Round(([double]$cs.TotalPhysicalMemory / 1GB), 1)
    if ($memoryGiB -ge 8) {
        Add-Check 'ram' 'PASS' "${memoryGiB} GiB installed"
    } else {
        Add-Check 'ram' 'WARN' "${memoryGiB} GiB installed; 8 GiB recommended for endpoint lab"
    }
} catch {
    Add-Check 'ram' 'WARN' 'Could not read installed RAM'
}

try {
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
    $freeGiB = [math]::Round(([double]$disk.FreeSpace / 1GB), 1)
    if ($freeGiB -ge 20) {
        Add-Check 'system_disk' 'PASS' "${freeGiB} GiB free on C:"
    } else {
        Add-Check 'system_disk' 'WARN' "${freeGiB} GiB free on C:; allow at least 20 GiB for staging/logs"
    }
} catch {
    Add-Check 'system_disk' 'WARN' 'Could not read C: free disk space'
}

try {
    $log = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
    if ($log.IsEnabled) {
        Add-Check 'sysmon_log' 'PASS' 'Sysmon Operational event channel is enabled'
    } else {
        Add-Check 'sysmon_log' 'WARN' 'Sysmon Operational event channel exists but is disabled'
    }
} catch {
    Add-Check 'sysmon_log' 'NOT_RUN' 'Sysmon channel not available; install/validate separately in the lab'
}

try {
    $event = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = 1
    } -MaxEvents 1 -ErrorAction Stop
    if ($null -ne $event) {
        Add-Check 'sysmon_process_create' 'PASS' ('Observed Event ID 1 at ' + $event.TimeCreated.ToUniversalTime().ToString('o'))
    }
} catch {
    Add-Check 'sysmon_process_create' 'NOT_RUN' 'No readable Sysmon Event ID 1 yet; trigger a benign process locally'
}

if (Test-LoopbackPort -Port 3310) {
    Add-Check 'clamd_loopback' 'PASS' 'Local TCP 127.0.0.1:3310 accepts connections (signature health NOT verified)'
} else {
    Add-Check 'clamd_loopback' 'NOT_RUN' 'No ClamAV daemon listening on TCP 127.0.0.1:3310'
}

if ($null -ne (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Add-Check 'cargo' 'PASS' 'Cargo executable found on PATH (build not yet verified)'
} else {
    Add-Check 'cargo' 'NOT_RUN' 'Cargo not on PATH; install Rust/MSVC tools before compiling agent'
}

if ($null -ne (Get-Command ssh -ErrorAction SilentlyContinue)) {
    Add-Check 'ssh_client' 'PASS' 'OpenSSH client available (Linux host connectivity not verified)'
} else {
    Add-Check 'ssh_client' 'NOT_RUN' 'OpenSSH client not present; needed for secure localhost tunnel'
}

try {
    $health = Invoke-RestMethod -Method Get -Uri 'http://127.0.0.1:8080/api/health' -TimeoutSec 3 -ErrorAction Stop
    if ($health.status -eq 'ok' -and $health.mode -eq 'development') {
        Add-Check 'backend_tunnel' 'PASS' 'Go development API health reachable on Windows loopback (tunnel/source unverified)'
    } else {
        Add-Check 'backend_tunnel' 'WARN' 'Unexpected response on Windows loopback port 8080'
    }
} catch {
    Add-Check 'backend_tunnel' 'NOT_RUN' 'No Go development API on Windows loopback:8080; establish SSH tunnel after Linux SSH is enabled'
}

Add-Check 'remote_access' 'MANUAL' 'External RDP/firewall exposure cannot be verified locally; restrict to VPN or trusted admin IP, use NLA and rotate previously disclosed admin password'
Add-Check 'real_clamav_signatures' 'MANUAL' 'Confirm genuine ClamAV engine/signature database version and EICAR-only lab test separately; open port alone is not proof'
Add-Check 'production_ready' 'BLOCKED' 'Development token, missing mTLS and missing persistent authenticated telemetry prohibit production deployment'

$result = [pscustomobject]@{
    schema_version = 1
    collected_utc = (Get-Date).ToUniversalTime().ToString('o')
    hostname = $env:COMPUTERNAME
    os = $osCaption
    build = $osBuild
    checks = @($checks.ToArray())
}

if ($Json) {
    $result | ConvertTo-Json -Depth 5
} else {
    $result.checks | Format-Table name, status, detail -Wrap -AutoSize
}

if ($RequireReady -and (@($result.checks | Where-Object { $_.status -in @('WARN','NOT_RUN') }).Count -gt 0)) {
    exit 2
}
