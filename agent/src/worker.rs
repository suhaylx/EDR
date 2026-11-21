//! LAB-ONLY, single-shot localhost control plane scanner. This is NOT a
//! background-protection service, tenant identity, or an enrolled device.
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{clamav, open_lab_scan_target, scan_lab_file};

#[derive(Debug, Deserialize)]
struct ScanLease {
    id: String,
    agent_id: String,
    lease_id: String,
    scan_type: String,
    #[serde(default)]
    path: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ScanCompletion {
    agent_id: String,
    lease_id: String,
    engine: &'static str,
    verdict: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    threat_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    detail: String,
}

fn error(kind: io::ErrorKind, msg: impl Into<String>) -> io::Error {
    io::Error::new(kind, msg.into())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 96 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
}

// UTF-8 length boundaries must be respected for the Go server's field limits.
fn bounded(mut value: String, max: usize) -> String {
    if value.len() > max {
        let mut end = max;
        while !value.is_char_boundary(end) { end -= 1; }
        value.truncate(end);
    }
    value
}

fn completion(job: &ScanLease, verdict: &'static str, threat_name: String, detail: String) -> ScanCompletion {
    ScanCompletion {
        agent_id: job.agent_id.clone(),
        lease_id: job.lease_id.clone(),
        engine: "clamav",
        verdict,
        threat_name: bounded(threat_name, 256),
        detail: bounded(detail, 1024),
    }
}

fn validate_lease(job: &ScanLease, agent: &str) -> io::Result<()> {
    if !valid_id(&job.id) || !valid_id(&job.lease_id) || !valid_id(&job.agent_id) || job.agent_id != agent {
        return Err(error(io::ErrorKind::PermissionDenied, "invalid scan lease or agent mismatch"));
    }
    if job.scan_type != "path" && job.scan_type != "quick" && job.scan_type != "full" {
        return Err(error(io::ErrorKind::InvalidData, "unsupported lease scan type"));
    }
    if job.scan_type != "path" && !job.path.is_empty() {
        return Err(error(io::ErrorKind::InvalidData, "non-path job contains path"));
    }
    if job.scan_type == "path" && (job.path.is_empty() || !Path::new(&job.path).is_absolute()) {
        return Err(error(io::ErrorKind::InvalidData, "path scan requires absolute local path"));
    }
    Ok(())
}

// On Linux, bind the scan to the *opened* policy root, not to a pathname
// checked separately from opening. openat2 resolves the entire relative path
// atomically with respect to symlinks, mount crossings and traversal escapes.
// Linux < 5.6, unsupported filesystems or kernels fail closed (no fallback).
#[cfg(target_os = "linux")]
fn open_scoped_lab_file(path: &str, root: &Path) -> io::Result<std::fs::File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    let target = Path::new(path);
    if !root.is_absolute() || !target.is_absolute() {
        return Err(error(io::ErrorKind::PermissionDenied, "absolute scan root and target required"));
    }
    let root = fs::canonicalize(root)?;
    if root.parent().is_none() || !root.is_dir() {
        return Err(error(io::ErrorKind::PermissionDenied, "invalid lab scan root"));
    }
    let relative = target.strip_prefix(&root).map_err(|_| {
        error(io::ErrorKind::PermissionDenied, "target is not beneath lab scan root")
    })?;
    if relative.as_os_str().is_empty() ||
        !relative.components().all(|component| matches!(component, Component::Normal(_))) {
        return Err(error(io::ErrorKind::PermissionDenied, "invalid relative scan target"));
    }

    let root_c = CString::new(root.as_os_str().as_bytes())
        .map_err(|_| error(io::ErrorKind::InvalidInput, "NUL in root"))?;
    // O_PATH allows a directory capability without needing directory read
    // privileges. O_NOFOLLOW plus metadata prevents a swapped final root link.
    let root_fd = unsafe {
        libc::open(root_c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY |
            libc::O_CLOEXEC | libc::O_NOFOLLOW)
    };
    if root_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let root_handle = unsafe { std::fs::File::from_raw_fd(root_fd) };
    if !root_handle.metadata()?.is_dir() {
        return Err(error(io::ErrorKind::PermissionDenied, "scan root is not a directory"));
    }

    let relative_c = CString::new(relative.as_os_str().as_bytes())
        .map_err(|_| error(io::ErrorKind::InvalidInput, "NUL in scan target"))?;
    // openat2 UAPI: NO_XDEV=0x01, NO_SYMLINKS=0x04, BENEATH=0x08.
    // O_NONBLOCK prevents a malicious FIFO/device path from hanging during
    // open; the opened handle must still pass a regular-file type check.
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC |
            libc::O_NOFOLLOW | libc::O_NONBLOCK) as u64,
        mode: 0,
        resolve: 0x01 | 0x04 | 0x08,
    };
    let fd = unsafe {
        libc::syscall(libc::SYS_openat2, root_handle.as_raw_fd(),
            relative_c.as_ptr(), &how as *const OpenHow,
            std::mem::size_of::<OpenHow>())
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd as i32) };
    let info = file.metadata()?;
    if !info.is_file() || info.len() > crate::MAX_SCAN_BYTES {
        return Err(error(io::ErrorKind::InvalidInput,
            "target must be a regular file within scan size cap"));
    }
    Ok(file)
}

// Windows and other non-Linux platforms retain the limited lab path check.
// Windows production must use reparse-safe, handle-relative file opens.
#[cfg(not(target_os = "linux"))]
fn open_scoped_lab_file(path: &str, root: &Path) -> io::Result<std::fs::File> {
    let target = allowed_lab_file(path, root)?;
    open_lab_scan_target(&target)
}

// Fail closed: both supplied root and target are resolved before file open.
// This reduces symlink traversal but is not a TOCTOU-safe production sandbox.
fn allowed_lab_file(path: &str, root: &Path) -> io::Result<PathBuf> {
    if !Path::new(path).is_absolute() {
        return Err(error(io::ErrorKind::PermissionDenied, "scan target must be absolute"));
    }
    let root = fs::canonicalize(root)?;
    if !root.is_dir() || root.parent().is_none() {
        return Err(error(io::ErrorKind::PermissionDenied, "invalid lab scan root"));
    }
    let target = fs::canonicalize(path)?;
    if target == root || !target.starts_with(&root) {
        return Err(error(io::ErrorKind::PermissionDenied, "scan outside configured lab root refused"));
    }
    Ok(target)
}

fn scan_one(job: &ScanLease, root: &Path, socket: &str) -> ScanCompletion {
    if job.scan_type != "path" {
        return completion(job, "unscanned", String::new(),
            "quick/full scan profiles require endpoint policy and are not implemented".into());
    }
    let outcome = (|| -> io::Result<clamav::Verdict> {
        let mut file = open_scoped_lab_file(&job.path, root)?;
        scan_lab_file(&mut file, socket)
    })();
    match outcome {
        Ok(clamav::Verdict::CleanBySignature) => completion(job, "clean_by_signature", String::new(),
            "ClamAV signature check completed; a clean signature verdict is not proof of safety".into()),
        Ok(clamav::Verdict::Malicious(name)) => completion(job, "malicious", name, String::new()),
        Ok(clamav::Verdict::ScannerError(message)) => completion(job, "error", String::new(),
            format!("ClamAV daemon returned error: {message}")),
        Err(e) => completion(job, "error", String::new(), format!("Scan not completed: {e}")),
    }
}

// Development HTTP is intentionally restricted to 127.0.0.1, and never used
// for production command delivery. No user-provided hostname or redirects.
fn api_port() -> io::Result<u16> {
    let value = env::var("TURANSEC_DEV_API_PORT").unwrap_or_else(|_| "8080".into());
    let port = value.parse::<u16>()
        .map_err(|_| error(io::ErrorKind::InvalidInput, "invalid localhost API port"))?;
    if port == 0 { return Err(error(io::ErrorKind::InvalidInput, "invalid localhost API port")); }
    Ok(port)
}

fn body_bounded(response: ureq::Response) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    response.into_reader().take(8193).read_to_end(&mut buf)?;
    if buf.len() > 8192 { return Err(error(io::ErrorKind::InvalidData, "oversized development API response")); }
    Ok(buf)
}

fn url(port: u16, path: &str) -> String { format!("http://127.0.0.1:{port}{path}") }

pub fn run(agent_id: &str) -> io::Result<()> {
    if !valid_id(agent_id) { return Err(error(io::ErrorKind::InvalidInput, "invalid agent ID")); }
    let token = env::var("EDR_DEV_TOKEN")
        .map_err(|_| error(io::ErrorKind::PermissionDenied, "EDR_DEV_TOKEN is required for lab API"))?;
    if token.len() < 16 || token.len() > 1024 || token.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return Err(error(io::ErrorKind::PermissionDenied, "unsafe development API token"));
    }
    let root = env::var("TURANSEC_LAB_SCAN_ROOT")
        .map_err(|_| error(io::ErrorKind::PermissionDenied, "TURANSEC_LAB_SCAN_ROOT is mandatory"))?;
    let root = Path::new(&root);
    if !root.is_absolute() || !root.is_dir() || fs::canonicalize(root)?.parent().is_none() {
        return Err(error(io::ErrorKind::PermissionDenied, "scan root must be a non-root absolute local directory"));
    }
    let port = api_port()?;
    let client = ureq::AgentBuilder::new().redirects(0)
        .timeout_connect(Duration::from_secs(3))
        .timeout_read(Duration::from_secs(8))
        .timeout_write(Duration::from_secs(8)).build();
    let auth = format!("Bearer {token}");
    let lease_path = format!("/api/agents/{agent_id}/scan-lease");
    let res = client.post(&url(port, &lease_path)).set("Authorization", &auth)
        .set("Content-Type", "application/json").send_string("{}")
        .map_err(|e| error(io::ErrorKind::ConnectionAborted, format!("lease request failed: {e}")))?;
    if res.status() == 204 { println!("lab_scan_worker=no_job"); return Ok(()); }
    if res.status() != 200 { return Err(error(io::ErrorKind::InvalidData, "unexpected lease status")); }
    let lease_bytes = body_bounded(res)?;
    let lease: ScanLease = serde_json::from_slice(&lease_bytes)
        .map_err(|_| error(io::ErrorKind::InvalidData, "invalid development lease JSON"))?;
    validate_lease(&lease, agent_id)?;

    #[cfg(unix)]
    let socket = env::var("TURANSEC_CLAMD_SOCKET").unwrap_or_else(|_| "/run/clamav/clamd.ctl".into());
    #[cfg(windows)]
    let socket = "127.0.0.1:3310".to_owned();
    let result = scan_one(&lease, root, &socket);
    let body = serde_json::to_vec(&result)
        .map_err(|_| error(io::ErrorKind::InvalidData, "could not serialize scan result"))?;
    let completion_url = url(port, &format!("/api/scan-jobs/{}/result", lease.id));
    let result_resp = client.post(&completion_url).set("Authorization", &auth)
        .set("Content-Type", "application/json").send_bytes(&body)
        .map_err(|e| error(io::ErrorKind::ConnectionAborted, format!("result reporting failed: {e}")))?;
    if result_resp.status() != 200 {
        return Err(error(io::ErrorKind::InvalidData, "scan result was not accepted"));
    }
    println!("lab_scan_worker=reported verdict={}", result.verdict);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn lease() -> ScanLease {
        ScanLease { id: "job-01".into(), agent_id: "lab01".into(), lease_id: "lease-01".into(),
            scan_type: "path".into(), path: "/tmp/example.txt".into() }
    }
    #[test]
    fn rejects_malformed_cross_agent_lease() {
        let mut job = lease();
        assert!(validate_lease(&job, "other-agent").is_err());
        job.agent_id = "lab01".into();
        job.lease_id = "contains/slash".into();
        assert!(validate_lease(&job, "lab01").is_err());
        job.lease_id = "lease-01".into();
        job.path = "relative.txt".into();
        assert!(validate_lease(&job, "lab01").is_err());
    }
    #[test]
    fn quick_and_full_never_claim_scanned() {
        let mut job = lease();
        job.scan_type = "quick".into(); job.path.clear();
        assert!(validate_lease(&job, "lab01").is_ok());
        let c = scan_one(&job, Path::new("/"), "not-used");
        assert_eq!(c.verdict, "unscanned");
        assert!(c.threat_name.is_empty());
    }
    #[test]
    fn token_safe_ids_and_unicode_are_bounded() {
        for value in ["abc/def", "\n", "", "foo bar"] { assert!(!valid_id(value)); }
        assert!(valid_id("agent_12.foo"));
        assert!(bounded("😀".repeat(300), 1024).len() <= 1024);
        let bytes = serde_json::to_vec(&completion(&lease(), "malicious", "Eicar-Test-Signature".into(), String::new())).unwrap();
        assert!(String::from_utf8(bytes).unwrap().contains("Eicar-Test-Signature"));
    }
    #[cfg(unix)]
    #[test]
    fn one_shot_worker_uses_real_instream_protocol_over_local_socket() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        for (reply, expected) in [
            ("stream: OK\0", "clean_by_signature"),
            ("stream: Eicar-Test-Signature FOUND\0", "malicious"),
            ("stream: scanner down ERROR\0", "error"),
        ] {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!("turansec-worker-scan-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&root).unwrap();
            let file = root.join("sample.txt");
            std::fs::write(&file, b"benign-test-bytes").unwrap();
            let socket = root.join("clamd.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let reply = reply.as_bytes().to_vec();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut cmd = [0; 10];
                stream.read_exact(&mut cmd).unwrap();
                assert_eq!(&cmd, b"zINSTREAM\0");
                let mut all = Vec::new();
                loop {
                    let mut length = [0u8; 4];
                    stream.read_exact(&mut length).unwrap();
                    let size = u32::from_be_bytes(length) as usize;
                    if size == 0 { break; }
                    let mut buf = vec![0u8; size];
                    stream.read_exact(&mut buf).unwrap();
                    all.extend_from_slice(&buf);
                }
                assert_eq!(all, b"benign-test-bytes");
                stream.write_all(&reply).unwrap();
            });
            let mut job = lease();
            job.path = file.to_str().unwrap().into();
            let result = scan_one(&job, &root, socket.to_str().unwrap());
            server.join().unwrap();
            assert_eq!(result.verdict, expected);
            if expected == "malicious" { assert_eq!(result.threat_name, "Eicar-Test-Signature"); }
            std::fs::remove_dir_all(root).unwrap();
        }
    }
    #[cfg(unix)]
    #[test]
    fn canonical_path_must_stay_inside_root() {
        let root = std::env::temp_dir().join(format!("turansec-worker-paths-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let good = root.join("good.txt");
        std::fs::write(&good, b"benign").unwrap();
        assert_eq!(allowed_lab_file(good.to_str().unwrap(), &root).unwrap(), good);
        assert!(allowed_lab_file("/etc/hosts", &root).is_err());
        assert!(allowed_lab_file("../../etc/hosts", &root).is_err());
        use std::os::unix::fs::symlink;
        let escaped = root.join("escaped-link");
        symlink("/etc/hosts", &escaped).unwrap();
        assert!(allowed_lab_file(escaped.to_str().unwrap(), &root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
