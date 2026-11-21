//! BE-076..080: enrolled-device HTTPS transport; no bearer/dev-token fallback.
//! Caller must provision a verified client cert/key and trusted TuranSec CA.
use crate::scan_jobs::{parse_claim, valid_identity, ClaimedJob, CompleteRequest, RenewRequest};
use reqwest::blocking::Client;
use reqwest::tls::Version;
use reqwest::{Certificate, Identity, Url};
use std::env;
use std::fs;
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

fn read_key(path: &Path) -> io::Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(reject("private key path must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(reject("client key must not be group/world accessible"));
        }
    }
    fs::read(path)
}

fn env_required(name: &str) -> io::Result<String> {
    env::var(name).map_err(|_| reject("required mTLS agent setting missing"))
}

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
        let ca = fs::read(env_required("TURANSEC_MTLS_CA_PEM")?)?;
        let cert = fs::read(env_required("TURANSEC_MTLS_CERT_PEM")?)?;
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
}
