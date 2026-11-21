//! TuranSec EDR agent prototype: independent core and Sysmon worker heartbeat.
//! Does NOT install Sysmon, collect real OS events, or quarantine any files.
#[allow(dead_code)]
mod clamav;
#[allow(dead_code)]
mod scan_jobs;
#[allow(dead_code)]
mod scan_mtls;
#[allow(dead_code)]
mod scan_file;
mod scan_runner;

use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let args:Vec<String>=std::env::args().collect();
    if args.len()>1 {
        if args.len()==2 && args[1]=="--heartbeat-mtls" {
            if let Err(e)=scan_runner::heartbeat_once() {
                eprintln!("agent_mtls_heartbeat_failed={:?}",e.kind());
                std::process::exit(2);
            }
            return;
        }
        if args.len()==2 && args[1]=="--scan-once-mtls" {
            if let Err(e)=scan_runner::run_once() {
                eprintln!("agent_mtls_scan_failed={:?}",e.kind());
                std::process::exit(2);
            }
            return;
        }
        eprintln!("unsupported agent arguments; supported lab modes: --scan-once-mtls, --heartbeat-mtls");
        std::process::exit(2);
    }
    println!("TuranSec EDR agent LAB scaffold -- no endpoint protection active");
    let (tx, rx) = mpsc::sync_channel::<String>(32);
    let sysmon_worker = thread::spawn(move || {
        // Placeholder collector: replace with platform-specific Sysmon event subscription.
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
