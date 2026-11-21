//! BE-093: one-shot lab worker, with lease heartbeat and durable verdict API.
//! Not an autostart endpoint service. Refuses a boolean-only success fallback.
use crate::scan_file::{scan_claimed_file, Outcome};
use crate::scan_mtls::AgentClient;
use std::env;
use std::fs;
use std::io::{self};
use std::path::Path;
use std::sync::{Arc,mpsc,atomic::{AtomicBool,Ordering}};
use std::thread;
use std::time::Duration;

fn deny(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied,msg)
}

fn root_from_env() -> io::Result<std::path::PathBuf> {
    let value = env::var("TURANSEC_LAB_SCAN_ROOT")
        .map_err(|_| deny("lab scan root is required"))?;
    let original=Path::new(&value);
    if !original.is_absolute() || fs::symlink_metadata(original)?.file_type().is_symlink() {
        return Err(deny("scan root must be an absolute non-symlink directory"));
    }
    let root=fs::canonicalize(original)?;
    if !root.is_dir() || root.parent().is_none() {
        return Err(deny("scan root cannot be filesystem root"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(&root)?.permissions().mode() & 0o022 != 0 {
            return Err(deny("lab scan root must not be group/world writable"));
        }
    }
    Ok(root)
}

fn safe_verdict(outcome: &Outcome) -> (&'static str,String,&'static str) {
    match outcome {
        Outcome::CleanBySignature => ("clean_by_signature",String::new(),"ClamAV signature scan completed; not proof of safety"),
        Outcome::Malicious(name) if name.len()<=256
            && !name.is_empty() && !name.chars().any(char::is_control) =>
            ("malicious",name.clone(),"Signature matched; investigate and contain by approved policy"),
        Outcome::Malicious(_) | Outcome::Error =>
            ("error",String::new(),"Scan could not produce a valid trusted ClamAV verdict"),
    }
}

pub fn run_once() -> io::Result<()> {
    // Authorization is checked BEFORE acquiring any remote lease.
    let root=root_from_env()?;
    let client=AgentClient::from_env()?;
    let job=match client.claim()? {
        None => {println!("agent_mtls_claim=no_job");return Ok(());}
        Some(job)=>job,
    };
    // Initial extension prevents immediately expiring during clamd startup.
    // Failure denies execution; recovery is handled by the server queue.
    client.renew(&job,120)?;

    let (stop_tx,stop_rx)=mpsc::sync_channel::<()>(1);
    let lease_healthy=Arc::new(AtomicBool::new(true));
    let flag=lease_healthy.clone();
    let renewal_client=client.clone();
    let renewal_job=job.clone();
    let renew_worker=thread::spawn(move|| {
        loop {
            match stop_rx.recv_timeout(Duration::from_secs(20)) {
                Ok(())|Err(mpsc::RecvTimeoutError::Disconnected)=>break,
                Err(mpsc::RecvTimeoutError::Timeout)=>{
                    if renewal_client.renew(&renewal_job,120).is_err() {
                        flag.store(false,Ordering::SeqCst);
                        break;
                    }
                }
            }
        }
    });

    let verdict=scan_claimed_file(&job,&root);
    let _=stop_tx.send(());
    if renew_worker.join().is_err() || !lease_healthy.load(Ordering::SeqCst) {
        return Err(deny("scan lease renewal failed; result not reported as success"));
    }
    let (kind,signature,detail)=safe_verdict(&verdict);
    client.complete_result(&job,kind,&signature,detail)?;
    // Never print file path, private key, lease token, or signature in agent logs.
    println!("agent_mtls_scan_result=stored classification={kind}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn be093_retains_malicious_classification() {
        let (kind,name,_) = safe_verdict(&Outcome::Malicious("Lab-Signature".into()));
        assert_eq!(kind,"malicious");
        assert_eq!(name,"Lab-Signature");
    }
    #[test]
    fn be094_refuses_invalid_signature_as_valid_detection() {
        let (kind,_,_) = safe_verdict(&Outcome::Malicious("bad\nname".into()));
        assert_eq!(kind,"error");
    }
    #[test]
    fn be095_scanner_error_cannot_be_clean() {
        let (kind,_,_) = safe_verdict(&Outcome::Error);
        assert_eq!(kind,"error");
    }
}
