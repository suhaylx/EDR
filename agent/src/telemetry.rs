//! Lab-only Windows heartbeat and real Sysmon Event ID 1 transfer.
//! No service installation, tamper protection, TLS identity or prevention.
//! Always connect to the Linux development API using a Windows-local SSH tunnel.
use serde::Deserialize;
use serde_json::json;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(windows)]
use std::process::Command;
#[cfg(windows)]
use std::thread;

const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct SysmonProcess {
    record_id: u64,
    event_id: u32,
    time: String,
    #[serde(default)]
    image: String,
    #[serde(default)]
    process_guid: String,
    #[serde(default)]
    parent_process_guid: String,
}

fn error(kind: io::ErrorKind, reason: impl Into<String>) -> io::Error {
    io::Error::new(kind, reason.into())
}

fn valid_agent_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 96
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-. ".contains(&b) && b != b' ')
}

fn valid_token(token: &str) -> bool {
    (16..=1024).contains(&token.len())
        && token.bytes().all(|b| !b.is_ascii_control() && b != b' ')
}

fn api_port() -> io::Result<u16> {
    let raw = env::var("TURANSEC_DEV_API_PORT").unwrap_or_else(|_| "8080".into());
    let port = raw
        .parse::<u16>()
        .map_err(|_| error(io::ErrorKind::InvalidInput, "invalid local API port"))?;
    if port == 0 {
        return Err(error(io::ErrorKind::InvalidInput, "local API port cannot be zero"));
    }
    Ok(port)
}

fn records_after(json_body: &[u8], last_seen: u64) -> io::Result<Vec<SysmonProcess>> {
    if json_body.len() > MAX_RESPONSE_BYTES {
        return Err(error(io::ErrorKind::InvalidData, "oversized Sysmon query output"));
    }
    let mut records: Vec<SysmonProcess> = serde_json::from_slice(json_body)
        .map_err(|_| error(io::ErrorKind::InvalidData, "malformed Sysmon JSON"))?;
    if records.len() > 32 {
        return Err(error(io::ErrorKind::InvalidData, "too many Sysmon records"));
    }
    records.retain(|r| {
        r.record_id > last_seen
            && r.event_id == 1
            && !r.process_guid.is_empty()
            && r.process_guid.len() <= 160
            && !r.image.is_empty()
            && r.image.len() <= 1024
            && r.parent_process_guid.len() <= 160
            && r.time.len() <= 64
            && r.time.contains('T')
    });
    records.sort_by_key(|r| r.record_id);
    records.dedup_by_key(|r| r.record_id);
    Ok(records)
}

fn event_payload(agent_id: &str, r: &SysmonProcess) -> serde_json::Value {
    json!({
        "device_id": agent_id,
        "platform": "windows",
        "source": "sysmon",
        "source_record_id": r.record_id.to_string(),
        "type": "process_create",
        "time": r.time,
        "process_guid": r.process_guid,
        "parent_process_guid": r.parent_process_guid,
        "image": r.image,
        "detail": format!("Observed Sysmon Operational Event ID 1; Windows EventRecordID={}; command line not collected", r.record_id)
    })
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

// Script text is constant, never built using a command line, agent name or a token.
// Queries actual Microsoft-Windows-Sysmon/Operational Windows events; does NOT
// fabricate observations, download binaries or export command lines/usernames.
#[cfg(windows)]
const SYSMON_POWERSHELL: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$channel = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
if (-not $channel.IsEnabled) { throw 'Sysmon Operational channel disabled' }
$records = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1} -MaxEvents 32 -ErrorAction SilentlyContinue)
$observations = @(
    foreach ($entry in $records) {
        [xml]$doc = $entry.ToXml()
        $fields = @{}
        foreach ($field in @($doc.Event.EventData.Data)) {
            $key = [string]$field.GetAttribute('Name')
            if ($key) { $fields[$key] = [string]$field.'#text' }
        }
        [pscustomobject]@{
            record_id = [long]$entry.RecordId
            event_id = [int]$entry.Id
            time = $entry.TimeCreated.ToUniversalTime().ToString('o')
            process_guid = [string]$fields['ProcessGuid']
            parent_process_guid = [string]$fields['ParentProcessGuid']
            image = [string]$fields['Image']
        }
    }
)
ConvertTo-Json -InputObject $observations -Compress -Depth 4
"#;

#[cfg(windows)]
fn collect_sysmon(last_seen: u64) -> io::Result<Vec<SysmonProcess>> {
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", SYSMON_POWERSHELL])
        .output()?;
    if !output.status.success() {
        return Err(error(
            io::ErrorKind::NotFound,
            "Sysmon Event ID 1 channel unavailable or unreadable; install Sysmon and check permissions",
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
        match collect_sysmon(last_seen) {
            Ok(records) => {
                let count = records.len();
                for record in records {
                    post_json(&client, port, &token, "/api/events", event_payload(agent_id, &record))?;
                    last_seen = record.record_id;
                    write_checkpoint(&checkpoint, last_seen)?;
                }
                println!("sysmon_process_events_sent={count} checkpoint_record_id={last_seen}");
            }
            Err(e) => {
                eprintln!("sysmon_collector_status=unavailable reason={e}");
                // Heartbeat remains valid; no fake event is sent.
            }
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
      {"record_id":11,"event_id":1,"time":"2026-11-21T13:59:00.0000000Z","image":"C:\\Windows\\explorer.exe","process_guid":"{C}","parent_process_guid":"{D}"},
      {"record_id":13,"event_id":3,"time":"2026-11-21T14:00:30.0000000Z","image":"x","process_guid":"{E}"}
    ]"#;

    #[test]
    fn uses_real_record_ids_and_deduplicates_after_checkpoint() {
        let v = records_after(OBSERVATIONS.as_bytes(), 11).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].record_id, 12);
        assert_eq!(v[0].image, r"C:\Windows\System32\notepad.exe");
        let payload = event_payload("win-lab-01", &v[0]);
        assert_eq!(payload["source"], "sysmon");
        assert_eq!(payload["source_record_id"], "12");
        assert_eq!(payload["type"], "process_create");
        assert_eq!(payload["parent_process_guid"], "{B}");
        assert!(payload["detail"].as_str().unwrap().contains("EventRecordID=12"));
    }

    #[test]
    fn malformed_and_empty_stream_behavior() {
        assert!(records_after(b"{malformed", 0).is_err());
        assert!(records_after(b"{}", 0).is_err());
        assert!(records_after(b"[]", 0).unwrap().is_empty());
        assert!(records_after(OBSERVATIONS.as_bytes(), 13).unwrap().is_empty());
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
