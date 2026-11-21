#requires -Version 5.1
# Native PowerShell parser and read-only smoke validation. No test credentials.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$target = Join-Path $PSScriptRoot 'windows-lab-preflight.ps1'
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($target, [ref]$tokens, [ref]$errors) | Out-Null
if (@($errors).Count -gt 0) {
    throw ('PowerShell syntax errors: ' + (($errors | ForEach-Object { $_.Message }) -join '; '))
}
$raw = & $target -Json
$r = ($raw | Out-String | ConvertFrom-Json)
if ($r.schema_version -ne 1) { throw 'Invalid preflight report schema' }
$names = @($r.checks | ForEach-Object { $_.name })
foreach ($required in @('os','ram','system_disk','sysmon_log','sysmon_process_create','clamd_loopback','cargo','ssh_client','backend_tunnel','remote_access','real_clamav_signatures','production_ready')) {
    if ($names -notcontains $required) { throw "Missing readiness check: $required" }
}
if (@($r.checks | Where-Object { $_.name -eq 'production_ready' -and $_.status -eq 'BLOCKED' }).Count -ne 1) {
    throw 'Production readiness must be blocked in the lab preflight'
}
Write-Host 'Windows laboratory preflight parser and schema smoke checks passed.'
