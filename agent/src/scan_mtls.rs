//! BE-076..080: enrolled-device HTTPS transport; no bearer/dev-token fallback.
//! Caller must provision a verified client cert/key and trusted TuranSec CA.
use crate::scan_jobs::{parse_claim, valid_identity, ClaimedJob, CompleteRequest, RenewRequest};
use reqwest::blocking::Client;
use reqwest::tls::Version;
use reqwest::{Certificate, Identity, Url};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::io::{self};
use std::path::Path;
use std::time::Duration;

fn reject(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, msg)
}

pub fn validated_origin(s: &str) -> io::Result<Url> {
    let u = Url::parse(s).map_err(|_| reject("invalid agent server URL"))?;
    if u.scheme() != "https" || u.host_str().is_none()
        || !u.username().is_empty() || u.password().is_some()
        || u.path() != "/" || u.query().is_some() || u.fragment().is_some()
        || s.trim() != s
    {
        return Err(reject("agent server must be a bare HTTPS origin"));
    }
    Ok(u)
}

const MAX_PEM_BYTES: u64 = 1024 * 1024;

// BE-106..110: bounded, no-follow PEM reads; private keys must be owner-only
// on Unix. Windows ACL enforcement is an explicit release gate.
fn read_pem(path: &Path, private: bool) -> io::Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink()
        || meta.len() == 0 || meta.len() > MAX_PEM_BYTES {
        return Err(reject("credential file must be bounded, regular and non-symlink"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if private && meta.permissions().mode() & 0o077 != 0 {
            return Err(reject("private key must not be group/world accessible"));
        }
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file: File = options.open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() == 0 || opened.len() > MAX_PEM_BYTES {
        return Err(reject("credential file changed while opening"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if opened.dev() != meta.dev() || opened.ino() != meta.ino()
           || (private && opened.permissions().mode() & 0o077 != 0) {
            return Err(reject("credential file changed or permissions unsafe"));
        }
    }
    let mut bytes = Vec::new();
    file.take(MAX_PEM_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_PEM_BYTES {
        return Err(reject("credential content is empty or oversized"));
    }
    Ok(bytes)
}

fn env_required(name: &str) -> io::Result<String> {
    env::var(name).map_err(|_| reject("required mTLS agent setting missing"))
}

#[derive(Clone)]
pub struct AgentClient {
    http: Client,
    server: Url,
    tenant: String,
    agent: String,
}

impl AgentClient {
    pub fn from_env() -> io::Result<Self> {
        let origin = env_required("TURANSEC_MTLS_ORIGIN")?;
        let tenant = env_required("TURANSEC_MTLS_TENANT_ID")?;
        let agent = env_required("TURANSEC_MTLS_AGENT_ID")?;
        let ca = read_pem(Path::new(&env_required("TURANSEC_MTLS_CA_PEM")?),false)?;
        let cert = read_pem(Path::new(&env_required("TURANSEC_MTLS_CERT_PEM")?),false)?;
        let key = read_pem(Path::new(&env_required("TURANSEC_MTLS_KEY_PEM")?),true)?;
        Self::new(&origin, &tenant, &agent, &ca, &cert, &key)
    }

    pub fn new(origin: &str, tenant: &str, agent: &str, ca: &[u8], cert: &[u8], key: &[u8]) -> io::Result<Self> {
        let server = validated_origin(origin)?;
        if !valid_identity(tenant) || !valid_identity(agent) {
            return Err(reject("invalid enrolled tenant/device identity"));
        }
        let root = Certificate::from_pem(ca).map_err(|_| reject("invalid private CA certificate"))?;
        let mut client_identity = Vec::with_capacity(cert.len()+key.len()+1);
        client_identity.extend_from_slice(cert);
        client_identity.push(b'\n');
        client_identity.extend_from_slice(key);
        let identity = Identity::from_pem(&client_identity)
            .map_err(|_| reject("invalid enrolled client cert/key"))?;
        // No OS/web trust roots, proxies, redirects, plaintext or TLS 1.2.
        let http = Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .add_root_certificate(root)
            .identity(identity)
            .min_tls_version(Version::TLS_1_3)
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(4))
            .timeout(Duration::from_secs(12))
            .build().map_err(|_| reject("could not initialize agent mTLS"))?;
        Ok(Self {http,server,tenant:tenant.into(),agent:agent.into()})
    }

    fn endpoint(&self, operation: &str) -> Url {
        let suffix = format!("/agent/v1/tenants/{}/agents/{}/scan-jobs/{operation}",
            self.tenant, self.agent);
        self.server.join(&suffix).expect("validated URI segments")
    }

    // BE-125: signed transport binds this status to the enrolled certificate.
    // Reported versions are untrusted observational telemetry, not attestation.
    pub fn heartbeat(&self, platform: &str, agent_version: &str,
        clamav_version: &str, signature_version: &str, scan_ready: bool) -> io::Result<()> {
        #[derive(serde::Serialize)]
        struct Report<'a> {
            platform: &'a str, agent_version: &'a str,
            clamav_version: &'a str, signature_version: &'a str,
            scan_ready: bool,
        }
        if !["windows","linux"].contains(&platform) || agent_version.is_empty()
           || agent_version.len()>64 || clamav_version.len()>64 ||
           signature_version.len()>96 {
            return Err(reject("invalid heartbeat capability report"));
        }
        let response = self.http.post(self.endpoint_heartbeat())
            .json(&Report{platform,agent_version,clamav_version,
                signature_version,scan_ready})
            .send().map_err(|_| reject("heartbeat transport failed"))?;
        match response.status().as_u16() {
            204 => Ok(()),
            _ => Err(reject("heartbeat was rejected")),
        }
    }
    fn endpoint_heartbeat(&self) -> Url {
        let suffix=format!("/agent/v1/tenants/{}/agents/{}/heartbeat",
            self.tenant,self.agent);
        self.server.join(&suffix).expect("validated URI segments")
    }

    pub fn claim(&self) -> io::Result<Option<ClaimedJob>> {
        // Claim is bodyless: JSON {} is explicitly rejected by the backend.
        let response = self.http.post(self.endpoint("claim")).body("")
            .send().map_err(|_| reject("scan claim transport failed"))?;
        match response.status().as_u16() {
            204 => Ok(None),
            200 => parse_claim(response).map(Some),
            _ => Err(reject("scan claim was not authorized or available")),
        }
    }

    pub fn renew(&self, job: &ClaimedJob, lease_seconds: u16) -> io::Result<()> {
        job.validate()?;
        if !(5..=300).contains(&lease_seconds) {
            return Err(reject("invalid renewal duration"));
        }
        let response = self.http.post(self.endpoint("renew"))
            .json(&RenewRequest{job_id:&job.job_id, lease_token:&job.lease_token,lease_seconds})
            .send().map_err(|_| reject("scan renewal transport failed"))?;
        match response.status().as_u16() {
            204 => Ok(()),
            409 => Err(reject("scan lease is stale or revoked")),
            _ => Err(reject("scan renewal rejected")),
        }
    }

    pub fn complete(&self, job: &ClaimedJob, success: bool) -> io::Result<()> {
        job.validate()?;
        let response = self.http.post(self.endpoint("complete"))
            .json(&CompleteRequest{job_id:&job.job_id,lease_token:&job.lease_token,success})
            .send().map_err(|_| reject("scan completion transport failed"))?;
        match response.status().as_u16() {
            204 => Ok(()),
            409 => Err(reject("scan completion lease is stale or revoked")),
            _ => Err(reject("scan completion rejected")),
        }
    }
    pub fn complete_result(&self, job: &ClaimedJob, verdict: &str, threat_name: &str, detail: &str) -> io::Result<()> {
        job.validate()?;
        let valid_verdict = match verdict {
            "malicious" => !threat_name.is_empty(),
            "clean_by_signature"|"error"|"unscanned" => threat_name.is_empty(),
            _ => false,
        };
        if !valid_verdict || threat_name.len() > 256 || detail.len() > 1024
           || threat_name.contains('\0') || detail.contains('\0') {
            return Err(reject("invalid ClamAV result"));
        }
        #[derive(serde::Serialize)]
        struct ResultPayload<'a> {
            job_id: &'a str, lease_token: &'a str, verdict: &'a str,
            threat_name: &'a str, detail: &'a str,
        }
        let payload = ResultPayload{job_id:&job.job_id,lease_token:&job.lease_token,
            verdict,threat_name,detail};
        let response = self.http.post(self.endpoint("complete-result"))
            .json(&payload).send().map_err(|_| reject("scan verdict transport failed"))?;
        match response.status().as_u16() {
            204 => Ok(()),
            409 => Err(reject("scan verdict rejected: expired or revoked lease")),
            _ => Err(reject("scan verdict was not persisted")),
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize,Ordering};
    static PEM_ID: AtomicUsize = AtomicUsize::new(0);
    fn fixture(data: &[u8]) -> std::path::PathBuf {
        let n = PEM_ID.fetch_add(1,Ordering::SeqCst);
        let path=std::env::temp_dir().join(format!(
            "turansec-agent-cred-{}-{n}.pem",std::process::id()));
        fs::write(&path,data).unwrap();
        path
    }
    #[test]
    fn be106_reads_small_regular_pem_file() {
        let path=fixture(b"test-pem-data");
        assert_eq!(read_pem(&path,false).unwrap(),b"test-pem-data");
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn be107_rejects_empty_and_oversized_pem() {
        let empty=fixture(b"");
        assert!(read_pem(&empty,false).is_err());
        fs::remove_file(empty).unwrap();
        let big=fixture(b"x");
        File::options().write(true).open(&big).unwrap()
            .set_len(MAX_PEM_BYTES+1).unwrap();
        assert!(read_pem(&big,false).is_err());
        fs::remove_file(big).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn be108_rejects_symlinked_ca_or_private_key() {
        use std::os::unix::fs::symlink;
        let path=fixture(b"test-pem-data");
        let link=path.with_extension("link");
        symlink(&path,&link).unwrap();
        assert!(read_pem(&link,false).is_err());
        assert!(read_pem(&link,true).is_err());
        fs::remove_file(link).unwrap();
        fs::remove_file(path).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn be109_requires_owner_only_private_key() {
        use std::os::unix::fs::PermissionsExt;
        let path=fixture(b"test-pem-data");
        fs::set_permissions(&path,fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_pem(&path,true).is_err());
        fs::set_permissions(&path,fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_pem(&path,true).is_ok());
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn be110_rejects_directory_as_credential() {
        let dir=std::env::temp_dir();
        assert!(read_pem(&dir,false).is_err());
    }
    #[test]
    fn be076_rejects_plaintext() {
        assert!(validated_origin("http://localhost:8080").is_err());
    }
    #[test]
    fn be077_rejects_url_credentials_and_query() {
        assert!(validated_origin("https://user:pass@edr.test").is_err());
        assert!(validated_origin("https://edr.test/?tenant=other").is_err());
    }
    #[test]
    fn be078_rejects_redirectable_path_and_fragment() {
        assert!(validated_origin("https://edr.test/api").is_err());
        assert!(validated_origin("https://edr.test/#hidden").is_err());
    }
    #[test]
    fn be079_accepts_bare_https_origin() {
        assert!(validated_origin("https://edr.example:8443").is_ok());
    }
    #[test]
    fn be080_rejects_missing_identity_before_network() {
        let err = AgentClient::new("https://edr.test", "..", "win01", b"", b"", b"");
        assert!(err.is_err());
    }
}
