//! BE-081..085: lab-only single regular file ClamAV scan.
//! No quarantine/deletion. Path canonicalization is NOT a race-free sandbox;
//! run only against an immutable administrator-owned scan directory.
use crate::{clamav, scan_jobs::{ClaimedJob, MAX_SCAN_FILE}};
use std::fs::{self, File, OpenOptions};
use std::io::{self};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

#[derive(PartialEq, Eq, Debug)]
pub enum Outcome {
    CleanBySignature,
    Malicious(String),
    Error,
}

fn deny(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, msg)
}

pub fn resolve_target(root: &Path, target: &str) -> io::Result<PathBuf> {
    if !root.is_absolute() || !Path::new(target).is_absolute() {
        return Err(deny("scan paths must be absolute"));
    }
    if Path::new(target).components().any(|part|
        matches!(part, Component::ParentDir | Component::CurDir)) {
        return Err(deny("relative traversal components forbidden in scan target"));
    }
    if fs::symlink_metadata(root)?.file_type().is_symlink() {
        return Err(deny("lab root must not be a symlink"));
    }
    #[cfg(windows)]
    if target.starts_with(r"\\") {
        return Err(deny("UNC/network scan targets are not authorized"));
    }
    let root = fs::canonicalize(root)?;
    if !root.is_dir() || root.parent().is_none() {
        return Err(deny("lab scan root cannot be the filesystem root"));
    }
    let requested = Path::new(target);
    let original = fs::symlink_metadata(requested)?;
    if original.file_type().is_symlink() || !original.file_type().is_file() {
        return Err(deny("only regular non-symlink files are allowed"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(&root)?.permissions().mode() & 0o022 != 0 {
            return Err(deny("lab root cannot be writable by group or other"));
        }
    }
    let target = fs::canonicalize(requested)?;
    if target == root || !target.starts_with(&root) {
        return Err(deny("scan target escapes authorized lab root"));
    }
    Ok(target)
}


#[cfg(unix)]
fn open_verified(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)
}
#[cfg(not(unix))]
fn open_verified(path: &Path) -> io::Result<File> {
    // Windows remains lab-only: a full reparse-point/ACL safe open is pending.
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(deny("symlink final target forbidden"));
    }
    File::open(path)
}

pub fn open_bounded(root: &Path, target: &str) -> io::Result<File> {
    let path = resolve_target(root,target)?;
    let before = fs::metadata(&path)?;
    if !before.is_file() || before.len() > MAX_SCAN_FILE {
        return Err(deny("scan target is not a bounded regular file"));
    }
    // BE-103: O_NOFOLLOW closes a final-component symlink-swap window on Unix.
    // Ancestor directory races still require a future openat2-style sandbox.
    let file = open_verified(&path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() > MAX_SCAN_FILE {
        return Err(deny("opened scan target exceeds size cap"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev() != before.dev() || opened.ino() != before.ino() {
            return Err(deny("scan target changed while opening"));
        }
    }
    Ok(file)
}

#[cfg(unix)]
fn clamd_scan(file: &mut File) -> io::Result<clamav::Verdict> {
    use std::os::unix::net::UnixStream;
    let socket = std::env::var("TURANSEC_CLAMD_SOCKET")
        .unwrap_or_else(|_| "/run/clamav/clamd.ctl".to_owned());
    if !Path::new(&socket).is_absolute() {
        return Err(deny("clamd socket must be an absolute local Unix socket"));
    }
    let mut connection = UnixStream::connect(socket)?;
    connection.set_read_timeout(Some(Duration::from_secs(20)))?;
    connection.set_write_timeout(Some(Duration::from_secs(20)))?;
    clamav::scan_stream(&mut connection,file,MAX_SCAN_FILE)
}

#[cfg(windows)]
fn clamd_scan(file: &mut File) -> io::Result<clamav::Verdict> {
    use std::net::TcpStream;
    // Windows lab clamd must only bind loopback, never expose 3310 externally.
    let addr = "127.0.0.1:3310".parse().expect("static loopback IP");
    let mut connection = TcpStream::connect_timeout(&addr,Duration::from_secs(3))?;
    connection.set_read_timeout(Some(Duration::from_secs(20)))?;
    connection.set_write_timeout(Some(Duration::from_secs(20)))?;
    clamav::scan_stream(&mut connection,file,MAX_SCAN_FILE)
}

/// BE-125: clamd daemon health probe. A PONG is liveness, not proof
/// that signatures are current, nor remote device integrity attestation.
pub fn clamd_ready() -> bool {
    use std::io::{Read, Write};
    #[cfg(unix)]
    {
        use std::os::unix::net::UnixStream;
        let socket=std::env::var("TURANSEC_CLAMD_SOCKET")
            .unwrap_or_else(|_| "/run/clamav/clamd.ctl".to_owned());
        if !Path::new(&socket).is_absolute() {return false}
        if let Ok(mut connection)=UnixStream::connect(socket) {
            let _=connection.set_read_timeout(Some(Duration::from_secs(2)));
            let _=connection.set_write_timeout(Some(Duration::from_secs(2)));
            let mut answer=[0u8;5];
            return connection.write_all(b"zPING\0").is_ok() &&
                connection.read_exact(&mut answer).is_ok() && &answer==b"PONG\0";
        }
    }
    #[cfg(windows)]
    {
        use std::net::TcpStream;
        let addr="127.0.0.1:3310".parse().expect("static loopback IP");
        if let Ok(mut connection)=TcpStream::connect_timeout(&addr,Duration::from_secs(2)) {
            let _=connection.set_read_timeout(Some(Duration::from_secs(2)));
            let _=connection.set_write_timeout(Some(Duration::from_secs(2)));
            let mut answer=[0u8;5];
            return connection.write_all(b"zPING\0").is_ok() &&
                connection.read_exact(&mut answer).is_ok() && &answer==b"PONG\0";
        }
    }
    false
}

pub fn scan_claimed_file(job: &ClaimedJob, root: &Path) -> Outcome {
    if job.validate().is_err() {
        return Outcome::Error;
    }
    let result = open_bounded(root,&job.scan_root).and_then(|mut file|clamd_scan(&mut file));
    match result {
        Ok(clamav::Verdict::CleanBySignature) => Outcome::CleanBySignature,
        Ok(clamav::Verdict::Malicious(name)) => Outcome::Malicious(name),
        Ok(clamav::Verdict::ScannerError(_)) | Err(_) => Outcome::Error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize,Ordering};
    static NEXT:AtomicUsize=AtomicUsize::new(0);
    fn fixture() -> PathBuf {
        let n=NEXT.fetch_add(1,Ordering::Relaxed);
        let root=std::env::temp_dir().join(format!("turansec-be081-085-{}-{n}",std::process::id()));
        fs::create_dir(&root).unwrap();
        root
    }
    #[test]
    fn be081_authorized_file_is_resolved() {
        let root=fixture();
        let p=root.join("sample");
        fs::write(&p,b"benign").unwrap();
        assert_eq!(resolve_target(&root,p.to_str().unwrap()).unwrap(),fs::canonicalize(&p).unwrap());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn be082_directory_and_relative_paths_are_denied() {
        let root=fixture();
        assert!(resolve_target(&root,"relative/sample").is_err());
        assert!(resolve_target(&root,root.to_str().unwrap()).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn be083_large_sparse_file_is_denied() {
        let root=fixture();
        let p=root.join("huge");
        File::create(&p).unwrap().set_len(MAX_SCAN_FILE+1).unwrap();
        assert!(open_bounded(&root,p.to_str().unwrap()).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn be084_symlink_escape_is_denied() {
        use std::os::unix::fs::symlink;
        let root=fixture();
        let p=root.join("escape");
        symlink("/etc/hosts",&p).unwrap();
        assert!(resolve_target(&root,p.to_str().unwrap()).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn be101_parent_directory_segments_are_denied() {
        let root=fixture();
        let file=root.join("sample");
        fs::write(&file,b"benign").unwrap();
        let disguised=format!("{}/notthere/../sample",root.display());
        assert!(resolve_target(&root,&disguised).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn be102_root_must_not_be_group_or_other_writable() {
        use std::os::unix::fs::PermissionsExt;
        let root=fixture();
        let file=root.join("sample");
        fs::write(&file,b"benign").unwrap();
        fs::set_permissions(&root,fs::Permissions::from_mode(0o777)).unwrap();
        assert!(resolve_target(&root,file.to_str().unwrap()).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn be103_unix_open_rejects_symlink_swap() {
        use std::os::unix::fs::symlink;
        let root=fixture();
        let outside=std::env::temp_dir().join(format!("turansec-outside-{}",std::process::id()));
        fs::write(&outside,b"not authorized").unwrap();
        let file=root.join("swapped");
        symlink(&outside,&file).unwrap();
        assert!(open_verified(&file).is_err());
        fs::remove_file(outside).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn be104_lab_root_symlink_is_denied() {
        let root=fixture();
        let nested=root.join("nested");
        fs::create_dir(&nested).unwrap();
        let p=nested.join("sample");
        fs::write(&p,b"benign").unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::symlink;
            let link=root.with_extension("symlink");
            symlink(&root,&link).unwrap();
            assert!(resolve_target(&link,p.to_str().unwrap()).is_err());
            fs::remove_file(link).unwrap();
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn be105_file_inside_root_still_opens() {
        let root=fixture();
        let file=root.join("ok.txt");
        fs::write(&file,b"benign").unwrap();
        assert_eq!(open_bounded(&root,file.to_str().unwrap()).unwrap().metadata().unwrap().len(),6);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn be085_missing_scanner_returns_error_not_clean() {
        let root=fixture();
        let j=ClaimedJob{
            job_id:"11111111-1111-4111-8111-111111111111".into(),
            lease_token:"22222222-2222-4222-8222-222222222222".into(),
            scan_root:root.join("missing").to_str().unwrap().into(),
            attempt_count:1,
        };
        assert_eq!(scan_claimed_file(&j,&root),Outcome::Error);
        fs::remove_dir_all(root).unwrap();
    }
}
