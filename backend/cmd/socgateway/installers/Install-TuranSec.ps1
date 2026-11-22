#Requires -Version 5.1
<#
TuranSec three-component Windows x64 deployment bundle (engineering pilot).
A signed TuranSec setup + approved ClamAV archive + Microsoft-signed Sysmon
are all required. Issued endpoint identity stays OUTSIDE the downloaded ZIP.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$IdentityDir,
  [Parameter(Mandatory=$true)][ValidatePattern('^[0-9A-Fa-f]{40,64}$')][string]$ApprovedAgentSigner,
  [switch]$AcceptSysmonEula,
  [switch]$CheckOnly,
  [switch]$Activate
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if (-not $AcceptSysmonEula) { throw 'Explicit Microsoft Sysmon EULA acceptance required' }
$root=$PSScriptRoot
$required=@('TuranSec-Agent-Setup.exe','ClamAV.zip','Sysmon64.exe')
$manifest=Get-Content -LiteralPath (Join-Path $root 'approved.json') -Raw | ConvertFrom-Json
$records=@($manifest.files)
if ($records.Count -ne 3) { throw 'Expected exactly three approved vendor artifacts' }
foreach ($name in $required) {
  $hits=@($records | Where-Object { $_.name -ceq $name })
  if ($hits.Count -ne 1 -or $hits[0].sha256 -cnotmatch '^[0-9a-fA-F]{64}$') { throw 'Invalid approved checksum' }
  $path=Join-Path $root $name
  $f=Get-Item -LiteralPath $path -Force -ErrorAction Stop
  if ($f.PSIsContainer -or ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
      $f.Length -lt 1 -or $f.Length -gt 314572800) { throw 'Unapproved or unsafe payload type' }
  if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $hits[0].sha256) { throw 'Vendor payload checksum mismatch' }
}
$identity=Get-Item -LiteralPath $IdentityDir -Force -ErrorAction Stop
if (-not $identity.PSIsContainer -or ($identity.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Absolute private enrollment directory required' }
foreach ($name in @('server-ca.pem','agent.pem','agent.key')) {
  $f=Get-Item -LiteralPath (Join-Path $identity.FullName $name) -Force -ErrorAction Stop
  if ($f.PSIsContainer -or ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $f.Length -lt 1) { throw 'Missing private enrollment input' }
}
$info=Get-Content -LiteralPath (Join-Path $root 'enrollment.json') -Raw | ConvertFrom-Json
if ($info.platform -cne 'windows' -or $info.tenant_id -cne 'lab' -or
    $info.agent_id -cnotmatch '^[A-Za-z0-9_.-]{1,96}$' -or $info.agent_id -in @('.','..') -or
    $info.credential_material_not_embedded -ne $true) { throw 'Malformed enrollment metadata' }
$setup=Join-Path $root 'TuranSec-Agent-Setup.exe'
$sysmon=Join-Path $root 'Sysmon64.exe'
$s=Get-AuthenticodeSignature -LiteralPath $setup
if ($s.Status -ne 'Valid' -or -not $s.SignerCertificate -or
    $s.SignerCertificate.Thumbprint -ine $ApprovedAgentSigner) { throw 'TuranSec signed installer publisher mismatch' }
$s=Get-AuthenticodeSignature -LiteralPath $sysmon
if ($s.Status -ne 'Valid' -or -not $s.SignerCertificate -or
    $s.SignerCertificate.Subject -notmatch 'Microsoft') { throw 'Sysmon Microsoft signature required' }
$staging=Join-Path $env:TEMP ('turansec-clamav-' + [guid]::NewGuid().ToString('N'))
New-Item -Path $staging -ItemType Directory | Out-Null
try {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $archive=[IO.Compression.ZipFile]::OpenRead((Join-Path $root 'ClamAV.zip'))
  try {
    foreach ($entry in $archive.Entries) {
      $n=$entry.FullName.Replace('\','/')
      if ($n.StartsWith('/') -or $n -match '(^|/)\.\.(/|$)|:|^\\') { throw 'Unsafe ClamAV archive entry' }
    }
  } finally { $archive.Dispose() }
  Expand-Archive -LiteralPath (Join-Path $root 'ClamAV.zip') -DestinationPath $staging
  $daemon=@(Get-ChildItem -LiteralPath $staging -Filter clamd.exe -File -Recurse)
  if ($daemon.Count -ne 1) { throw 'ClamAV ZIP must contain exactly one clamd.exe' }
  $source=$daemon[0].DirectoryName
  if (-not (Test-Path -LiteralPath (Join-Path $source 'freshclam.exe'))) { throw 'Missing Windows ClamAV updater' }
  & $setup --identity-dir $identity.FullName --tenant $info.tenant_id --agent-id $info.agent_id --sysmon $sysmon --clamav-dir $source --agent-signer $ApprovedAgentSigner --accept-sysmon-eula --check-only
  if ($LASTEXITCODE -ne 0) { throw 'TuranSec agent/certificate preflight failed' }
  if ($CheckOnly) { Write-Output 'All three staged payloads and enrollment passed preflight; no persistent changes.'; return }
  $principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required' }
  if (Get-Service clamd -ErrorAction SilentlyContinue) { throw 'Existing clamd service requires a reviewed upgrade' }
  $target=Join-Path $env:ProgramData 'TuranSec\Vendor\ClamAV'
  if ((Test-Path -LiteralPath $target) -or (Test-Path -LiteralPath (Join-Path $env:ProgramData 'TuranSec\Endpoint'))) {
    throw 'Existing endpoint files require a reviewed upgrade'
  }
  New-Item -Path $target -ItemType Directory -Force | Out-Null
  Copy-Item -Path (Join-Path $source '*') -Destination $target -Recurse -Force
  $db=Join-Path $target 'database'
  New-Item -Path $db -ItemType Directory -Force | Out-Null
  $dbpath=$db.Replace('\','/')
  @("DatabaseDirectory $dbpath","DatabaseMirror database.clamav.net") | Set-Content -LiteralPath (Join-Path $target 'freshclam.conf') -Encoding Ascii
  @("DatabaseDirectory $dbpath","TCPSocket 3310","TCPAddr 127.0.0.1") | Set-Content -LiteralPath (Join-Path $target 'clamd.conf') -Encoding Ascii
  $fresh=(Join-Path $target 'freshclam.exe')
  & $fresh ("--config-file=" + (Join-Path $target 'freshclam.conf'))
  if ($LASTEXITCODE -ne 0) { throw 'Signature update failed; agent not installed' }
  Push-Location $target
  try {
    & (Join-Path $target 'clamd.exe') --install-service
    if ($LASTEXITCODE -ne 0) { throw 'ClamAV service installation failed' }
  } finally { Pop-Location }
  Start-Service clamd
  $listeners=@(Get-NetTCPConnection -State Listen -LocalPort 3310 -ErrorAction SilentlyContinue)
  if (-not @($listeners | Where-Object { $_.LocalAddress -eq '127.0.0.1' }).Count -or
      @($listeners | Where-Object { $_.LocalAddress -ne '127.0.0.1' }).Count) {
    throw 'ClamAV must listen exclusively on 127.0.0.1:3310'
  }
  $installerArgs=@('--identity-dir',$identity.FullName,'--tenant',$info.tenant_id,'--agent-id',$info.agent_id,
          '--sysmon',$sysmon,'--clamav-dir',$target,'--agent-signer',$ApprovedAgentSigner,'--accept-sysmon-eula')
  if ($Activate) { $installerArgs += '--activate' }
  & $setup @installerArgs
  if ($LASTEXITCODE -ne 0) { throw 'TuranSec/Sysmon installation failed: review partially installed services before retrying' }
  Write-Output 'Three components installed; confirm endpoint enrollment, scanner health and separate Sysmon telemetry.'
} finally {
  if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Force -Recurse }
}
