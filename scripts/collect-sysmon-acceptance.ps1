#requires -Version 5.1
<#
Read-only, bounded Sysmon observation for an isolated Windows lab. Does not
install, reconfigure or restart Sysmon, execute a DLL, or collect raw command
lines/file contents. Event 11 is creation evidence, never module-load evidence.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{40}$')][string]$CandidateSha,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [ValidateRange(1,60)][int]$LookbackMinutes=15,
    [ValidateRange(1,2000)][int]$MaximumEvents=500
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $OutputPath){throw 'Refusing to overwrite existing evidence'}
function Hash-Text([string]$Text){
    $h=[System.Security.Cryptography.SHA256]::Create()
    try{return ([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))).Replace('-','').ToLowerInvariant())}
    finally{$h.Dispose()}
}
$started=(Get-Date).ToUniversalTime()
$observations=New-Object 'System.Collections.Generic.List[object]'
$status='NOT_RUN'
$truncated=$false
$os=Get-CimInstance Win32_OperatingSystem
try{
    $events=@(Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Sysmon/Operational'
        ProviderName='Microsoft-Windows-Sysmon'
        Id=1,7,11
        StartTime=(Get-Date).AddMinutes(-$LookbackMinutes)
    } -MaxEvents $MaximumEvents -ErrorAction Stop)
    $truncated=($events.Count -ge $MaximumEvents)
    foreach($event in $events){
        [xml]$xml=$event.ToXml()
        $provider=[string]$xml.Event.System.Provider.Name
        $channel=[string]$xml.Event.System.Channel
        $id=[int]$xml.Event.System.EventID
        if($provider -ne 'Microsoft-Windows-Sysmon' -or $channel -ne 'Microsoft-Windows-Sysmon/Operational' -or $id -notin @(1,7,11)){continue}
        $fields=@{}
        foreach($field in @($xml.Event.EventData.Data)){$fields[[string]$field.Name]=[string]$field.'#text'}
        $guid=[string]$fields['ProcessGuid']
        $parsed=[Guid]::Empty
        if(-not [Guid]::TryParse($guid,[ref]$parsed)){continue}
        $target=''
        if($id -eq 7){$target=[string]$fields['ImageLoaded']}
        if($id -eq 11){$target=[string]$fields['TargetFilename']}
        $observations.Add([pscustomobject]@{
            event_id=$id
            record_id=[long]$event.RecordId
            provider=$provider
            channel=$channel
            time_created_utc=$event.TimeCreated.ToUniversalTime().ToString('o')
            process_guid_sha256=(Hash-Text $guid.ToLowerInvariant())
            image_sha256=(Hash-Text ([string]$fields['Image']).ToLowerInvariant())
            target_path_sha256=$(if($target){Hash-Text $target.ToLowerInvariant()}else{$null})
            source_xml_sha256=(Hash-Text $event.ToXml())
            evidence_kind=$(if($id -eq 7){'module_load'}elseif($id -eq 11){'file_create_only'}else{'process_create'})
        })
    }
    if($observations.Count -gt 0){$status='OBSERVED'}
}catch{
    # No raw event/provider exception: it can include user paths or identities.
    $status='NOT_RUN'
}
$counts=[ordered]@{}
foreach($id in @(1,7,11)){$counts[[string]$id]=@($observations | Where-Object {$_.event_id -eq $id}).Count}
$report=[pscustomobject]@{
    schema=1
    candidate_sha=$CandidateSha
    collected_utc=$started.ToString('o')
    host_id_sha256=(Hash-Text $env:COMPUTERNAME.ToLowerInvariant())
    os=[pscustomobject]@{caption=[string]$os.Caption;build=[string]$os.BuildNumber;boot_time_utc=$os.LastBootUpTime.ToUniversalTime().ToString('o')}
    status=$status
    lookback_minutes=$LookbackMinutes
    event_limit=$MaximumEvents
    truncated=$truncated
    counts=$counts
    events=@($observations.ToArray())
    event7_observed=($counts['7'] -gt 0)
    event11_is_not_load=$true
    backend_ingestion_verified=$false
    detection_verdict='NOT_ESTABLISHED_BY_LOCAL_CHANNEL_OBSERVATION'
    deployment_authorization='not-granted'
}
$parent=Split-Path -Parent $OutputPath
if($parent -and -not (Test-Path -LiteralPath $parent)){New-Item -ItemType Directory -Path $parent | Out-Null}
$json=$report | ConvertTo-Json -Depth 8
$bytes=[Text.Encoding]::UTF8.GetBytes($json+[Environment]::NewLine)
$stream=[IO.File]::Open($OutputPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
Write-Output ('Sysmon observations saved; module-load evidence present: '+$report.event7_observed)
if(-not $report.event7_observed){exit 2}
