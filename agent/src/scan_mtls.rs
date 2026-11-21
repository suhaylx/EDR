//! BE-076..080: enrolled-device HTTPS transport; no bearer/dev-token fallback.
//! Caller must provision a verified client cert/key and trusted TuranSec CA.
use crate::scan_jobs::{parse_claim, valid_identity, ClaimedJob, CompleteRequest, RenewRequest};
use reqwest::blocking::Client;
use reqwest::tls::Version;
use reqwest::{Certificate, Identity, Url};
use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
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

// These bounds apply before parsing TLS material and are intentionally much
// larger than a conventional PEM key/certificate. Never read arbitrary-size
// files supplied through the agent environment.
const MAX_PRIVATE_KEY_BYTES: u64 = 64 * 1024;
const MAX_CERT_BUNDLE_BYTES: u64 = 1024 * 1024;

fn read_pem_bounded(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() == 0 || opened.len() > limit {
        return Err(reject("TLS certificate material must be a bounded regular file"));
    }
    let mut content = Vec::new();
    file.by_ref().take(limit + 1).read_to_end(&mut content)?;
    if content.is_empty() || (content.len() as u64) > limit {
        return Err(reject("TLS certificate material exceeded size limit"));
    }
    Ok(content)
}

fn read_key(path: &Path) -> io::Result<Vec<u8>> {
    let original = fs::symlink_metadata(path)?;
    if !original.is_file() || original.file_type().is_symlink() {
        return Err(reject("private key path must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if original.permissions().mode() & 0o077 != 0 {
            return Err(reject("client key must not be group/world accessible"));
        }
        // Open first; before reading any secret, check that the opened inode
        // still matches the non-symlink file we inspected. This closes the
        // check-then-fs::read path-substitution window on Unix.
        let mut file = File::open(path)?;
        let opened = file.metadata()?;
        if !opened.is_file() || opened.dev() != original.dev()
            || opened.ino() != original.ino()
            || opened.permissions().mode() & 0o077 != 0
            || opened.len() == 0 || opened.len() > MAX_PRIVATE_KEY_BYTES
        {
            return Err(reject("private key changed or has unsafe file permissions"));
        }
        let mut bytes = Vec::new();
        file.by_ref().take(MAX_PRIVATE_KEY_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.is_empty() || (bytes.len() as u64) > MAX_PRIVATE_KEY_BYTES {
            return Err(reject("client private key exceeded size limit"));
        }
        return Ok(bytes);
    }
    #[cfg(not(unix))]
    {
        // Windows ACL and reparse-point checks still require deployment-time
        // verification; a filesystem mode bit does not establish NTFS ACLs.
        read_pem_bounded(path, MAX_PRIVATE_KEY_BYTES)
    }
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
        let ca = read_pem_bounded(Path::new(&env_required("TURANSEC_MTLS_CA_PEM")?), MAX_CERT_BUNDLE_BYTES)?;
        let cert = read_pem_bounded(Path::new(&env_required("TURANSEC_MTLS_CERT_PEM")?), MAX_CERT_BUNDLE_BYTES)?;
        let key = read_key(Path::new(&env_required("TURANSEC_MTLS_KEY_PEM")?))?;
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

    // The material reader must not consume attacker-controlled huge files or
    // follow an on-disk client-key symlink as a substitute for enrollment.
    fn private_key_fixture(name: &str, contents: &[u8]) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "turansec-agent-mtls-{}-{}-{name}", std::process::id(), seq));
        std::fs::write(&path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path,
                std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    #[test]
    fn pm101_reads_only_bounded_private_key() {
        let p = private_key_fixture("key", b"test-only-private-key");
        let bytes = read_key(&p).unwrap();
        assert_eq!(bytes, b"test-only-private-key");
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn pm102_rejects_oversized_secret_and_cert_bundle() {
        let key = private_key_fixture("large-key", &vec![b'k'; (MAX_PRIVATE_KEY_BYTES + 1) as usize]);
        assert!(read_key(&key).is_err());
        std::fs::remove_file(key).unwrap();
        let ca = private_key_fixture("large-ca", &vec![b'c'; (MAX_CERT_BUNDLE_BYTES + 1) as usize]);
        assert!(read_pem_bounded(&ca, MAX_CERT_BUNDLE_BYTES).is_err());
        std::fs::remove_file(ca).unwrap();
    }

    #[test]
    fn pm103_rejects_empty_cert_material() {
        let ca = private_key_fixture("empty-ca", b"");
        assert!(read_pem_bounded(&ca, MAX_CERT_BUNDLE_BYTES).is_err());
        std::fs::remove_file(ca).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn pm104_rejects_world_readable_key_and_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let p = private_key_fixture("key-perms", b"test-only-key");
        std::fs::set_permissions(&p,
            std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_key(&p).is_err());
        std::fs::set_permissions(&p,
            std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = p.with_extension("symlink");
        symlink(&p, &link).unwrap();
        assert!(read_key(&link).is_err());
        std::fs::remove_file(&link).unwrap();
        std::fs::remove_file(p).unwrap();
    }
}
