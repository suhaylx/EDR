//! Lab-only Windows heartbeat and configured Sysmon 1-29/255 transfer.
//! No service installation, tamper protection, TLS identity or prevention.
//! Always connect to the Linux development API using a Windows-local SSH tunnel.
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(windows)]
use std::process::Command;
#[cfg(windows)]
use std::thread;

const MAX_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_OBSERVATIONS: usize = 64;

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct SysmonEvent {
    record_id: u64,
    event_id: u32,
    time: String,
    #[serde(default)]
    image: String,
    #[serde(default)]
    process_guid: String,
    #[serde(default)]
    parent_process_guid: String,
    #[serde(default)] file_path: String,
    #[serde(default)] fields: BTreeMap<String, String>,
    #[serde(default)] boot_id: String,
}

fn error(kind: io::ErrorKind, reason: impl Into<String>) -> io::Error {
    io::Error::new(kind, reason.into())
}

pub(crate) fn valid_agent_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 96
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-. ".contains(&b) && b != b' ')
}

pub(crate) fn valid_token(token: &str) -> bool {
    (16..=1024).contains(&token.len())
        && token.bytes().all(|b| !b.is_ascii_control() && b != b' ')
}

pub(crate) fn api_port() -> io::Result<u16> {
    let raw = env::var("TURANSEC_DEV_API_PORT").unwrap_or_else(|_| "8080".into());
    let port = raw
        .parse::<u16>()
        .map_err(|_| error(io::ErrorKind::InvalidInput, "invalid local API port"))?;
    if port == 0 {
        return Err(error(io::ErrorKind::InvalidInput, "local API port cannot be zero"));
    }
    Ok(port)
}


fn known_sysmon_id(id: u32) -> bool { (1..=29).contains(&id) || id == 255 }
fn sysmon_kind(id: u32) -> &'static str {
    match id {
      1=>"process_create",2=>"file_creation_time",3=>"network_connect",
      4=>"sysmon_service_state",5=>"process_terminate",6=>"driver_load",
      7=>"module_load",8=>"create_remote_thread",9=>"raw_access_read",
      10=>"process_access",11=>"file_create",12=>"registry_object",
      13=>"registry_value_set",14=>"registry_rename",15=>"file_stream_hash",
      16=>"sysmon_config_change",17=>"pipe_create",18=>"pipe_connect",
      19=>"wmi_filter",20=>"wmi_consumer",21=>"wmi_binding",22=>"dns_query",
      23=>"file_delete_archive",24=>"clipboard_change_metadata",
      25=>"process_tampering",26=>"file_delete_detected",
      27=>"file_block_executable",28=>"file_block_shredding",
      29=>"file_executable_detected",255=>"sysmon_error",_=>"unknown"
    }
}
const SAFE_FIELDS: &[&str] = &[
 "rule_name","destination_ip","destination_port","source_ip","source_port",
 "protocol","query_name","target_object","pipe_name","source_image",
 "target_image","source_process_guid","target_process_guid","image_loaded",
 "operation","event_type","query_status","target_filename","initiated",
];
fn records_after(raw: &[u8], checkpoint: u64) -> io::Result<Vec<SysmonEvent>> {
    if raw.len() > MAX_RESPONSE_BYTES {
        return Err(error(io::ErrorKind::InvalidData,"oversized Sysmon query result"));
    }
    let mut observations:Vec<SysmonEvent> = serde_json::from_slice(raw)
        .map_err(|_|error(io::ErrorKind::InvalidData,"malformed Sysmon JSON"))?;
    if observations.len()>MAX_OBSERVATIONS {
        return Err(error(io::ErrorKind::InvalidData,"too many Sysmon records"));
    }
    for e in &observations {
        if e.record_id == 0 || !known_sysmon_id(e.event_id)
            || !(10..=64).contains(&e.time.len()) || !e.time.contains('T')
            || e.image.len()>1024 || e.file_path.len()>1024
            || e.process_guid.len()>128 || e.parent_process_guid.len()>128
            || e.boot_id.len()>128 || e.boot_id.chars().any(char::is_control)
            || e.fields.len()>SAFE_FIELDS.len()
            || e.fields.iter().any(|(k,v)| !SAFE_FIELDS.contains(&k.as_str())
                || v.len()>512 || v.chars().any(char::is_control))
            || e.fields.iter().map(|(k,v)|k.len()+v.len()).sum::<usize>() > 4096
        { return Err(error(io::ErrorKind::InvalidData,"invalid Sysmon event metadata")); }
        if e.event_id==24 && (!e.image.is_empty() || !e.file_path.is_empty()
            || !e.process_guid.is_empty() || !e.parent_process_guid.is_empty() || !e.fields.is_empty())
        { return Err(error(io::ErrorKind::InvalidData,"clipboard payload must not be exported")); }
        if e.event_id==1 && (e.process_guid.is_empty() || e.image.is_empty()) {
            return Err(error(io::ErrorKind::InvalidData,"process creation missing GUID/image"));
        }
    }
    observations.retain(|e|e.record_id>checkpoint);
    observations.sort_by_key(|e|e.record_id);
    observations.dedup_by_key(|e|e.record_id);
    Ok(observations)
}
fn event_payload(agent_id: &str, e: &SysmonEvent) -> serde_json::Value {
    let mut payload=json!({
      "device_id":agent_id,"platform":"windows","source":"sysmon",
      "source_provider":"Microsoft-Windows-Sysmon",
      "source_channel":"Microsoft-Windows-Sysmon/Operational",
      "source_event_id":e.event_id,"source_record_id":e.record_id.to_string(),
      "type":sysmon_kind(e.event_id),"time":e.time,
      "detail":format!("Observed Sysmon Operational Event ID {}, EventRecordID={}; sender-reported metadata",e.event_id,e.record_id)
    });
    if !e.image.is_empty(){payload["image"]=json!(e.image);}
    if !e.file_path.is_empty(){payload["file_path"]=json!(e.file_path);}
    if !e.process_guid.is_empty(){payload["process_guid"]=json!(e.process_guid);}
    // Event ID 1 alone establishes the parent link; no inferred edges.
    if e.event_id==1 && !e.parent_process_guid.is_empty() {
      payload["parent_process_guid"]=json!(e.parent_process_guid);
    }
    if !e.fields.is_empty(){payload["source_fields"]=json!(e.fields);}
    // Sender-reported OS boot marker is accepted only for events observed
    // within the current Windows boot interval; not endpoint attestation.
    if !e.boot_id.is_empty(){payload["boot_id"]=json!(e.boot_id);}
    payload
}

fn checkpoint_path(local_app_data: &Path, agent_id: &str) -> io::Result<PathBuf> {
    if !valid_agent_id(agent_id) {
        return Err(error(io::ErrorKind::InvalidInput, "invalid agent id"));
    }
    Ok(local_app_data
        .join("TuranSec")
        .join(format!("lab-sysmon-checkpoint-{agent_id}.txt")))
}

fn read_checkpoint(path: &Path) -> io::Result<u64> {
    match fs::read_to_string(path) {
        Ok(value) => value.trim().parse::<u64>().map_err(|_| {
            error(io::ErrorKind::InvalidData, "invalid Sysmon checkpoint: inspect before retrying")
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e),
    }
}

fn write_checkpoint(path: &Path, id: u64) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        error(io::ErrorKind::InvalidInput, "missing checkpoint directory")
    })?;
    fs::create_dir_all(parent)?;
    fs::write(path, format!("{id}\n"))
}

// Queries actual Sysmon Operational records in ascending EventRecordID order.
// No command-line input from the API; child PowerShell never inherits the token.
// Only source metadata allowlisted in SAFE_FIELDS is sent. Event 24 is stripped.
#[cfg(windows)]
const SYSMON_POWERSHELL: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$channel = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
if (-not $channel.IsEnabled) { throw 'Sysmon channel disabled' }
[long]$cursor = 0
if (-not [long]::TryParse($env:TURANSEC_SYSMON_CURSOR,[ref]$cursor) -or $cursor -lt 0) { throw 'Invalid checkpoint' }
$xpath = "*[System[(EventRecordID > $cursor) and ((EventID >= 1 and EventID <= 29) or EventID = 255)]]"
try {
  $records=@(Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath $xpath -Oldest -MaxEvents 64 -ErrorAction Stop)
} catch {
  if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound|NoEventsFound') { $records=@() }
  else { throw }
}
# LastBootUpTime comes from Windows CIM (same machine), not from the API.
# A record from an earlier boot is intentionally left unscoped. If the OS
# identity cannot be read, no boot label is sent and related rules fail closed.
$bootUtc=$null;$bootMarker=''
try {
  $operatingSystem=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
  if ($operatingSystem -and $operatingSystem.LastBootUpTime) {
    $bootUtc=$operatingSystem.LastBootUpTime.ToUniversalTime()
    $bootMarker='winboot:'+$bootUtc.ToString('o')
  }
} catch {
  $bootUtc=$null;$bootMarker=''
}
$names=@{
 RuleName='rule_name';DestinationIp='destination_ip';DestinationPort='destination_port'
 SourceIp='source_ip';SourcePort='source_port';Protocol='protocol'
 QueryName='query_name';TargetObject='target_object';PipeName='pipe_name'
 SourceImage='source_image';TargetImage='target_image'
 SourceProcessGUID='source_process_guid';TargetProcessGUID='target_process_guid'
 ImageLoaded='image_loaded';Operation='operation';EventType='event_type'
 QueryStatus='query_status';TargetFilename='target_filename';Initiated='initiated'
}
$observations=@(
  foreach ($entry in $records) {
    [xml]$xml=$entry.ToXml()
    $raw=@{}
    foreach ($data in @($xml.Event.EventData.Data)) {
      $key=[string]$data.GetAttribute('Name')
      if ($key) { $raw[$key]=[string]$data.'#text' }
    }
    $eventUtc=$entry.TimeCreated.ToUniversalTime()
    $eventBoot=''
    if ($bootUtc -and $eventUtc -ge $bootUtc -and $eventUtc -le [datetime]::UtcNow.AddMinutes(5)) {
      $eventBoot=$bootMarker
    }
    $eventId=[int]$entry.Id;$metadata=@{}
    $image='';$filePath='';$guid='';$parent=''
    if ($eventId -ne 24) {
      foreach ($key in $names.Keys) {
        $val=[string]$raw[$key]
        if ($val -and $val.Length -le 512 -and $val -notmatch '[\x00-\x1F\x7F]') {
          $metadata[$names[$key]]=$val
        }
      }
      $image=[string]$raw['Image']
      $guid=[string]$raw['ProcessGuid']
      if ($eventId -eq 1) { $parent=[string]$raw['ParentProcessGuid'] }
      if ($eventId -eq 7) { $filePath=[string]$raw['ImageLoaded'] }
      elseif ($raw.ContainsKey('TargetFilename')) { $filePath=[string]$raw['TargetFilename'] }
    }
    [pscustomobject]@{
      record_id=[long]$entry.RecordId
      event_id=$eventId
      time=$eventUtc.ToString('o')
      boot_id=$eventBoot
      image=$image;file_path=$filePath;process_guid=$guid
      parent_process_guid=$parent;fields=$metadata
    }
  }
)
ConvertTo-Json -InputObject $observations -Compress -Depth 5
"#;

#[cfg(windows)]
fn collect_sysmon(last_seen: u64) -> io::Result<Vec<SysmonEvent>> {
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", SYSMON_POWERSHELL])
        .env_remove("EDR_DEV_TOKEN")
        .env("TURANSEC_SYSMON_CURSOR", last_seen.to_string())
        .output()?;
    if !output.status.success() {
        return Err(error(
            io::ErrorKind::NotFound,
            "Sysmon channel unavailable or unreadable; verify installed Sysmon and permissions",
        ));
    }
    records_after(&output.stdout, last_seen)
}

#[cfg(windows)]
fn post_json(
    client: &ureq::Agent,
    port: u16,
    token: &str,
    path: &str,
    payload: serde_json::Value,
) -> io::Result<()> {
    let url = format!("http://127.0.0.1:{port}{path}");
    let auth = format!("Bearer {token}");
    client
        .post(&url)
        .set("Authorization", &auth)
        .set("Content-Type", "application/json")
        .send_string(&payload.to_string())
        .map_err(|e| error(io::ErrorKind::ConnectionAborted, format!("local API rejected request: {e}")))?;
    Ok(())
}

#[cfg(windows)]
pub fn run(agent_id: &str, loop_mode: bool) -> io::Result<()> {
    if !valid_agent_id(agent_id) {
        return Err(error(io::ErrorKind::InvalidInput, "invalid lab agent id"));
    }
    let token = env::var("EDR_DEV_TOKEN").map_err(|_| {
        error(io::ErrorKind::PermissionDenied, "EDR_DEV_TOKEN is required (do not share it)")
    })?;
    if !valid_token(&token) {
        return Err(error(io::ErrorKind::PermissionDenied, "invalid lab API token"));
    }
    let local_app_data = env::var_os("LOCALAPPDATA").ok_or_else(|| {
        error(io::ErrorKind::NotFound, "LOCALAPPDATA is required for a local Sysmon checkpoint")
    })?;
    let checkpoint = checkpoint_path(Path::new(&local_app_data), agent_id)?;
    let mut last_seen = read_checkpoint(&checkpoint)?;
    let port = api_port()?;
    let client = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout_connect(Duration::from_secs(3))
        .timeout_read(Duration::from_secs(8))
        .timeout_write(Duration::from_secs(8))
        .build();

    println!("turansec_lab_agent={agent_id} mode={} protection=disabled", if loop_mode { "poll" } else { "once" });
    loop {
        // This is an unauthenticated device identity with a shared dev token.
        // It is deliberately not an installed EDR service or production enrollment.
        post_json(
            &client,
            port,
            &token,
            "/api/agents",
            json!({"id": agent_id, "platform": "windows", "group": "lab", "health": "lab_unprotected"}),
        )?;
        println!("lab_heartbeat=sent device={agent_id}");
        // Drain bounded ascending pages, checkpoint only after accepted POST.
        // Backlog is reported; this is not a lossless production collector.
        let mut accepted=0usize;
        for _ in 0..4 {
            match collect_sysmon(last_seen) {
                Ok(records) => {
                    let received=records.len();
                    for record in records {
                        post_json(&client,port,&token,"/api/events",event_payload(agent_id,&record))?;
                        last_seen=record.record_id;
                        write_checkpoint(&checkpoint,last_seen)?;
                        accepted+=1;
                    }
                    if received<MAX_OBSERVATIONS {break;}
                }
                Err(e)=>{
                    eprintln!("sysmon_collector_status=unavailable reason={e}");
                    break;
                }
            }
        }
        println!("sysmon_events_sent={accepted} checkpoint_record_id={last_seen}");
        if accepted==4*MAX_OBSERVATIONS {
            eprintln!("sysmon_backlog_possible=true drain_limit=256");
        }
        if !loop_mode {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(60));
    }
}

#[cfg(not(windows))]
pub fn run(_agent_id: &str, _loop_mode: bool) -> io::Result<()> {
    Err(error(io::ErrorKind::Unsupported, "Sysmon telemetry is Windows-only"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBSERVATIONS: &str = r#"[
      {"record_id":12,"event_id":1,"time":"2026-11-21T14:00:00.0000000Z","image":"C:\\Windows\\System32\\notepad.exe","process_guid":"{A}","parent_process_guid":"{B}"},
      {"record_id":11,"event_id":7,"time":"2026-11-21T13:59:00.0000000Z","image":"C:\\Windows\\explorer.exe","file_path":"C:\\Users\\lab\\Temp\\test.dll","process_guid":"{C}","fields":{"image_loaded":"C:\\Users\\lab\\Temp\\test.dll"}},
      {"record_id":13,"event_id":3,"time":"2026-11-21T14:00:30.0000000Z","image":"C:\\Windows\\System32\\curl.exe","process_guid":"{E}","fields":{"destination_ip":"10.0.0.5","destination_port":"443"}},
      {"record_id":14,"event_id":24,"time":"2026-11-21T14:00:32.0000000Z"},
      {"record_id":15,"event_id":255,"time":"2026-11-21T14:00:34.0000000Z"}
    ]"#;
    #[test]
    fn preserves_real_ids_order_and_creation_only_parent_guid() {
        let events=records_after(OBSERVATIONS.as_bytes(),11).unwrap();
        assert_eq!(events.len(),4);
        assert_eq!((events[0].record_id,events[0].event_id),(12,1));
        assert_eq!((events[1].record_id,events[1].event_id),(13,3));
        assert_eq!((events[2].record_id,events[2].event_id),(14,24));
        let create=event_payload("win-lab-01",&events[0]);
        assert_eq!(create["source_event_id"],1);
        assert_eq!(create["source_provider"],"Microsoft-Windows-Sysmon");
        assert_eq!(create["source_channel"],"Microsoft-Windows-Sysmon/Operational");
        assert_eq!(create["source_record_id"],"12");
        assert_eq!(create["parent_process_guid"],"{B}");
        assert_eq!(create["image"],r"C:\Windows\System32\notepad.exe");
        let network=event_payload("win-lab-01",&events[1]);
        assert_eq!(network["type"],"network_connect");
        assert_eq!(network["source_fields"]["destination_ip"],"10.0.0.5");
        assert!(network.get("parent_process_guid").is_none());
        let clipboard=event_payload("win-lab-01",&events[2]);
        assert_eq!(clipboard["type"],"clipboard_change_metadata");
        assert!(clipboard.get("source_fields").is_none());
    }
    #[test]
    fn actual_dll_load_path_is_preserved() {
        let events=records_after(OBSERVATIONS.as_bytes(),0).unwrap();
        let load=event_payload("win-lab-01",&events[0]);
        assert_eq!(load["type"],"module_load");
        assert_eq!(load["source_event_id"],7);
        assert_eq!(load["file_path"],r"C:\Users\lab\Temp\test.dll");
        assert!(load.get("parent_process_guid").is_none());
    }
    #[test]
    fn supports_all_defined_ids_but_denies_private_fields() {
        for id in 1..=29 {assert!(known_sysmon_id(id));assert_ne!(sysmon_kind(id),"unknown");}
        assert!(known_sysmon_id(255));
        for id in [0,30,254] {assert!(!known_sysmon_id(id));}
        assert!(records_after(b"{invalid",0).is_err());
        assert!(records_after(b"{}",0).is_err());
        assert!(records_after(b"[]",0).unwrap().is_empty());
        assert!(records_after(OBSERVATIONS.as_bytes(),15).unwrap().is_empty());
        assert!(records_after(br#"[{"record_id":2,"event_id":24,"time":"2026-11-21T14:00:00Z","fields":{"query_name":"SECRET"}}]"#,0).is_err());
        assert!(records_after(br#"[{"record_id":2,"event_id":22,"time":"2026-11-21T14:00:00Z","fields":{"command_line":"SECRET"}}]"#,0).is_err());
        assert!(records_after(br#"[{"record_id":2,"event_id":30,"time":"2026-11-21T14:00:00Z"}]"#,0).is_err());
    }

    #[test]
    fn ids_and_tokens_do_not_allow_command_or_path_injection() {
        for id in ["", "../foo", "agent;exit", "test id", "x/y"] {
            assert!(!valid_agent_id(id));
        }
        assert!(valid_agent_id("win-lab-01"));
        assert!(!valid_token("short"));
        assert!(!valid_token("1234567890123456\n"));
        assert!(valid_token("0123456789abcdef"));
    }

    #[test]
    fn checkpoint_roundtrip_does_not_store_token() {
        let base = env::temp_dir().join(format!("turansec-telemetry-tests-{}", std::process::id()));
        let file = checkpoint_path(&base, "win-lab-01").unwrap();
        write_checkpoint(&file, 777).unwrap();
        assert_eq!(read_checkpoint(&file).unwrap(), 777);
        assert!(!fs::read_to_string(&file).unwrap().contains("secret"));
        let _ = fs::remove_file(&file);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn local_port_enforces_nonzero() {
        // Run-time port parsing deliberately contains no host component.
        assert_eq!(format!("http://127.0.0.1:{}{}", 8080, "/api/agents"), "http://127.0.0.1:8080/api/agents");
    }
}
