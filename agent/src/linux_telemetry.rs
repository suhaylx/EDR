//! Linux LAB telemetry: observed /proc snapshots, not process-create events.
//! Read-only; no root privileges, kernel hooks, auditd, eBPF or prevention.
//! Operator must connect Go development API over a localhost SSH tunnel.
use serde_json::{json, Value};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::thread;
use std::time::Duration;

use crate::telemetry::{api_port, valid_agent_id, valid_token};

const MAX_SNAPSHOT: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessObservation {
    pid: u32,
    parent_pid: u32,
    start_ticks: u64,
    image: String,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

// proc stat: #4=PPID and #22=starttime, relative to field #3 after "(comm) ".
// Command names may contain spaces or closing parentheses.
fn parse_proc_stat(raw: &str) -> io::Result<(u32, u64)> {
    if raw.len() > 8192 {
        return Err(invalid("oversized proc stat"));
    }
    let close = raw.rfind(") ").ok_or_else(|| invalid("proc stat missing comm"))?;
    let fields: Vec<&str> = raw[close + 2..].split_whitespace().collect();
    if fields.len() < 20 {
        return Err(invalid("truncated proc stat"));
    }
    let parent_pid = fields[1].parse::<u32>().map_err(|_| invalid("invalid PPID"))?;
    let start_ticks = fields[19].parse::<u64>().map_err(|_| invalid("invalid starttime"))?;
    if start_ticks == 0 {
        return Err(invalid("missing kernel starttime"));
    }
    Ok((parent_pid, start_ticks))
}

fn read_observation(proc_root: &Path, pid: u32) -> io::Result<ProcessObservation> {
    let dir = proc_root.join(pid.to_string());
    let stat = fs::read_to_string(dir.join("stat"))?;
    let (parent_pid, start_ticks) = parse_proc_stat(&stat)?;
    // A raced-away process or an inaccessible exe symlink is omitted, not
    // fabricated from the reported kernel command name.
    let executable = fs::read_link(dir.join("exe"))?;
    let image = executable
        .to_str()
        .filter(|s| !s.is_empty() && s.len() <= 1024)
        .ok_or_else(|| invalid("non-UTF8 or oversized executable"))?
        .to_owned();
    Ok(ProcessObservation { pid, parent_pid, start_ticks, image })
}

fn snapshot(proc_root: &Path, own_pid: u32) -> io::Result<Vec<ProcessObservation>> {
    let mut pids = Vec::new();
    for entry in fs::read_dir(proc_root)? {
        let name = entry?.file_name();
        if let Ok(pid) = name.to_string_lossy().parse::<u32>() {
            if pid > 0 && pid != own_pid {
                pids.push(pid);
            }
        }
    }
    pids.sort_unstable();
    if own_pid != 0 {
        pids.insert(0, own_pid); // include own process in a non-root smoke test
    }
    let mut observations = Vec::new();
    for pid in pids {
        if let Ok(item) = read_observation(proc_root, pid) {
            observations.push(item);
            if observations.len() >= MAX_SNAPSHOT {
                break;
            }
        }
    }
    Ok(observations)
}

fn event_payload(agent_id: &str, item: &ProcessObservation) -> Value {
    json!({
        "device_id": agent_id,
        "platform": "linux",
        "source": "procfs",
        "source_record_id": format!("procfs:{}:{}", item.pid, item.start_ticks),
        "type": "process_observed",
        "image": item.image,
        // No process GUID, parent GUID, execution timestamp, or infection.
        "detail": format!(
            "Observed /proc inventory pid={} ppid={} start_ticks={}; not a process creation event",
            item.pid, item.parent_pid, item.start_ticks
        )
    })
}

fn post_json(
    client: &ureq::Agent,
    port: u16,
    token: &str,
    path: &str,
    payload: Value,
) -> io::Result<()> {
    let url = format!("http://127.0.0.1:{port}{path}");
    client.post(&url)
        .set("Authorization", &format!("Bearer {token}"))
        .set("Content-Type", "application/json")
        .send_string(&payload.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, format!("localhost lab API request failed: {e}")))?;
    Ok(())
}

pub fn run(agent_id: &str, loop_mode: bool) -> io::Result<()> {
    if !valid_agent_id(agent_id) {
        return Err(invalid("invalid Linux lab agent ID"));
    }
    let token = env::var("EDR_DEV_TOKEN").map_err(|_| {
        io::Error::new(io::ErrorKind::PermissionDenied, "EDR_DEV_TOKEN required (never log it)")
    })?;
    if !valid_token(&token) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "invalid lab bearer token"));
    }
    let port = api_port()?;
    let client = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout_connect(Duration::from_secs(3))
        .timeout_read(Duration::from_secs(8))
        .timeout_write(Duration::from_secs(8))
        .build();
    let mut sent = HashSet::<(u32, u64)>::new();
    println!("turansec_linux_lab_agent={agent_id} mode={} protection=disabled", if loop_mode { "poll" } else { "once" });
    loop {
        post_json(&client, port, &token, "/api/agents",
            json!({"id": agent_id, "platform": "linux", "group": "lab", "health": "lab_unprotected"}))?;
        println!("lab_heartbeat=sent device={agent_id}");
        let observed = snapshot(Path::new("/proc"), std::process::id())?;
        let mut posted = 0usize;
        for item in observed {
            let id = (item.pid, item.start_ticks);
            if sent.contains(&id) {
                continue;
            }
            post_json(&client, port, &token, "/api/events", event_payload(agent_id, &item))?;
            sent.insert(id);
            posted += 1;
        }
        println!("linux_procfs_observations_sent={posted} source=procfs_non_realtime");
        if !loop_mode {
            return Ok(());
        }
        // Bounded memory; the collector may resend older observations after
        // the bound is reached. This is NOT lossless or a real-time EDR feed.
        if sent.len() > 8192 {
            sent.clear();
        }
        thread::sleep(Duration::from_secs(60));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kernel_start_identity_and_parent_pid() {
        let mut f = vec!["0"; 20];
        f[0] = "S";
        f[1] = "7";
        f[19] = "12345";
        let line = format!("123 (odd process ) name) {}", f.join(" "));
        assert_eq!(parse_proc_stat(&line).unwrap(), (7, 12345));
        assert!(parse_proc_stat("123 (x) S 1").is_err());
        assert!(parse_proc_stat("missing parentheses").is_err());
    }

    #[test]
    fn produces_only_snapshot_evidence() {
        let item = ProcessObservation {
            pid: 42, parent_pid: 1, start_ticks: 321,
            image: "/usr/bin/true".to_owned(),
        };
        let event = event_payload("linux-lab-01", &item);
        assert_eq!(event["type"], "process_observed");
        assert_eq!(event["source"], "procfs");
        assert_eq!(event["source_record_id"], "procfs:42:321");
        assert!(event.get("process_guid").is_none());
        assert!(event.get("parent_process_guid").is_none());
        assert!(event.get("time").is_none());
    }

    #[test]
    fn captures_actual_process_if_proc_mounted() {
        if Path::new("/proc/self/stat").exists() {
            let items = snapshot(Path::new("/proc"), std::process::id()).unwrap();
            assert!(!items.is_empty());
            assert!(items.iter().any(|p| p.pid == std::process::id()));
        }
    }
}
