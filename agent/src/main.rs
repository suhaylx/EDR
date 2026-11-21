//! TuranSec EDR LAB agent. One product identity manages separate scanning and
//! Sysmon capabilities; this is not a production endpoint service.
mod clamav;
mod worker;
mod telemetry;

use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

const MAX_SCAN_BYTES: u64 = 128 * 1024 * 1024;

// A path passed to the lab CLI is local to the endpoint. In production, signed
// agent policy must also authorize it, and opening must guard against TOCTOU.
fn open_lab_scan_target(path: &Path) -> io::Result<File> {
    let meta = path.symlink_metadata()?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "scan target must be a regular non-symlink file"));
    }
    if meta.len() > MAX_SCAN_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "scan target exceeds lab size limit"));
    }
    let file = File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() > MAX_SCAN_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "scan target changed or is too large"));
    }
    Ok(file)
}

#[cfg(unix)]
fn scan_lab_file(file: &mut File, socket_path: &str) -> io::Result<clamav::Verdict> {
    use std::os::unix::net::UnixStream;
    let mut connection = UnixStream::connect(socket_path)?;
    connection.set_read_timeout(Some(Duration::from_secs(20)))?;
    connection.set_write_timeout(Some(Duration::from_secs(20)))?;
    clamav::scan_stream(&mut connection, file, MAX_SCAN_BYTES)
}

#[cfg(windows)]
fn scan_lab_file(file: &mut File, _socket_path: &str) -> io::Result<clamav::Verdict> {
    // Windows local development uses a ClamAV daemon bound to loopback only.
    // Do not open the unauthenticated clamd TCP protocol to the network.
    use std::net::TcpStream;
    let mut connection = TcpStream::connect_timeout(
        &"127.0.0.1:3310".parse().expect("valid loopback socket"),
        Duration::from_secs(3),
    )?;
    connection.set_read_timeout(Some(Duration::from_secs(20)))?;
    connection.set_write_timeout(Some(Duration::from_secs(20)))?;
    clamav::scan_stream(&mut connection, file, MAX_SCAN_BYTES)
}

fn scan_file_cli(args: &[String]) -> io::Result<()> {
    if args.len() != 3 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
            "usage: turansec-edr-agent --scan-file <absolute-local-regular-file>"));
    }
    let path = Path::new(&args[2]);
    if !path.is_absolute() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "absolute scan path required"));
    }
    let mut file = open_lab_scan_target(path)?;
    #[cfg(unix)]
    let socket_path = "/run/clamav/clamd.ctl";
    #[cfg(windows)]
    let socket_path = "127.0.0.1:3310";
    match scan_lab_file(&mut file, socket_path)? {
        clamav::Verdict::CleanBySignature => {
            println!("engine=clamav verdict=clean_by_signature (NOT proof of safety)");
            Ok(())
        }
        clamav::Verdict::Malicious(name) => {
            println!("engine=clamav verdict=malicious signature={name}");
            // A detection is an alert, never automatic deletion.
            Ok(())
        }
        clamav::Verdict::ScannerError(e) => Err(io::Error::other(format!("clamd scanner error: {e}"))),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        if args[1] == "--telemetry-once" || args[1] == "--telemetry-loop" {
            if args.len() != 3 {
                eprintln!("usage: --telemetry-once <lab-agent-id> or --telemetry-loop <lab-agent-id>");
                std::process::exit(2);
            }
            if let Err(e) = telemetry::run(&args[2], args[1] == "--telemetry-loop") {
                eprintln!("lab_telemetry_error={e}");
                std::process::exit(2);
            }
            return;
        }
        if args[1] == "--lease-and-scan" {
            if args.len() != 3 {
                eprintln!("usage: --lease-and-scan <registered-lab-agent-id>");
                std::process::exit(2);
            }
            if let Err(e) = worker::run(&args[2]) {
                eprintln!("lab_scan_worker_error={e}");
                std::process::exit(2);
            }
            return;
        }
        if args[1] == "--scan-file" {
            if let Err(e) = scan_file_cli(&args) {
                eprintln!("scan_error={e}");
                std::process::exit(2);
            }
            return;
        }
        eprintln!("unknown arguments; use --telemetry-once/--telemetry-loop <agent-id>, --scan-file <absolute-path>, or --lease-and-scan <agent-id>");
        std::process::exit(2);
    }
    println!("TuranSec EDR agent LAB scaffold -- background protection is NOT active");
    let (tx, rx) = mpsc::sync_channel::<String>(32);
    let sysmon_worker = thread::spawn(move || {
        // Placeholder collector: replace with platform-specific Sysmon subscription.
        let _ = tx.send("sysmon_collector_not_implemented".to_owned());
    });
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(2) {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(msg) => println!("collector_status={msg}"),
            Err(RecvTimeoutError::Timeout) => println!("edr_core_heartbeat=alive"),
            Err(RecvTimeoutError::Disconnected) => {
                println!("collector_disconnected; core remains alive");
                thread::sleep(Duration::from_millis(250));
            }
        }
    }
    if sysmon_worker.join().is_err() {
        eprintln!("sysmon worker failed; EDR core was not terminated");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lab_target_rejects_relative_missing_and_directory_paths() {
        assert!(open_lab_scan_target(Path::new("relative.txt")).is_err());
        assert!(open_lab_scan_target(Path::new("/no/such/turansec-test-file")).is_err());
        assert!(open_lab_scan_target(Path::new("/")).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn lab_target_does_not_follow_symlink() {
        use std::os::unix::fs::symlink;
        let target = std::env::temp_dir().join(format!("turansec-lab-link-{}", std::process::id()));
        symlink("/etc/hosts", &target).unwrap();
        assert!(open_lab_scan_target(&target).is_err());
        std::fs::remove_file(target).unwrap();
    }
}
