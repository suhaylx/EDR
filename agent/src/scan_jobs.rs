//! BE-071..075: wire protocol for an enrolled mTLS agent.
//! The server, not these strings, establishes tenant and agent identity.
//! Lease tokens are capabilities and must never appear in Debug output/logs.
use serde::{Deserialize, Serialize};
use std::io::{self, Read};

pub const MAX_CLAIM_BODY: usize = 8192;
pub const MAX_SCAN_FILE: u64 = 128 * 1024 * 1024;
pub const CLAIM_LEASE_SECONDS: u64 = 60;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimedJob {
    pub job_id: String,
    pub scan_root: String,
    pub attempt_count: u32,
    pub lease_token: String,
}

#[derive(Serialize)]
pub struct RenewRequest<'a> {
    pub job_id: &'a str,
    pub lease_token: &'a str,
    pub lease_seconds: u16,
}

#[derive(Serialize)]
pub struct CompleteRequest<'a> {
    pub job_id: &'a str,
    pub lease_token: &'a str,
    pub success: bool,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn valid_identity(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 96
        && value != "."
        && value != ".."
        && bytes.iter().all(|c| c.is_ascii_alphanumeric() || b"_-.".contains(c))
}

/// Reject terminal control and bidi-format spoofing in endpoint-provided
/// text before it is sent to the Go/PostgreSQL result contract.
pub fn unsafe_scan_text(value: &str) -> bool {
    value.chars().any(|ch| {
        ch.is_control()
            || ('\u{202a}'..='\u{202e}').contains(&ch)
            || ('\u{2066}'..='\u{2069}').contains(&ch)
            || ch == '\u{200e}' || ch == '\u{200f}'
    })
}

pub fn valid_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 { return false; }
    b.iter().enumerate().all(|(i,c)| {
        if [8, 13, 18, 23].contains(&i) { *c == b'-' } else { c.is_ascii_hexdigit() }
    })
}

impl ClaimedJob {
    pub fn validate(&self) -> io::Result<()> {
        if !valid_uuid(&self.job_id) || !valid_uuid(&self.lease_token) {
            return Err(invalid("invalid job or lease ID"));
        }
        if self.attempt_count == 0 || self.attempt_count > 20 {
            return Err(invalid("invalid attempt count"));
        }
        if self.scan_root.is_empty() || self.scan_root.len() > 4096
            || self.scan_root.contains('\0') {
            return Err(invalid("invalid scan target"));
        }
        Ok(())
    }
}

pub fn parse_claim<R: Read>(reader: R) -> io::Result<ClaimedJob> {
    let mut limited = reader.take((MAX_CLAIM_BODY + 1) as u64);
    let mut bytes = Vec::new();
    limited.read_to_end(&mut bytes)?;
    if bytes.len() > MAX_CLAIM_BODY { return Err(invalid("oversized claim response")); }
    let job: ClaimedJob = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("malformed claim response"))?;
    job.validate()?;
    Ok(job)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid_json() -> String {
        r#"{"job_id":"11111111-1111-4111-8111-111111111111","lease_token":"22222222-2222-4222-8222-222222222222","scan_root":"/lab/sample","attempt_count":1}"#.into()
    }
    #[test]
    fn qa_unsafe_text_rejects_controls_and_bidi() {
        for unsafe_value in ["\u{1b}[31m", "name\u{202e}spoof",
            "mark\u{200f}", "isolate\u{2066}", "tab\tname"] {
            assert!(unsafe_scan_text(unsafe_value));
        }
        assert!(!unsafe_scan_text("Legitimate-Signature-UTF8 café"));
    }
    #[test]
    fn be071_accepts_exact_contract() {
        let j = parse_claim(valid_json().as_bytes()).unwrap();
        assert_eq!(j.attempt_count, 1);
        assert_eq!(j.scan_root, "/lab/sample");
    }
    #[test]
    fn be072_rejects_unknown_fields_and_trailing_json() {
        let data = valid_json().replace(r#""attempt_count":1}"#, r#""attempt_count":1,"agent_id":"other"}"#);
        assert!(parse_claim(data.as_bytes()).is_err());
        assert!(parse_claim(format!("{}{}",valid_json(), "{}").as_bytes()).is_err());
    }
    #[test]
    fn be073_rejects_invalid_ids() {
        assert!(valid_identity("win01.lab"));
        for bad in ["", ".", "..", "../win01", "other/agent", "win 01"] {
            assert!(!valid_identity(bad), "accepted {bad}");
        }
        assert!(valid_uuid("11111111-1111-4111-8111-111111111111"));
        assert!(!valid_uuid("11111111-1111-4111-8111-11111111111x"));
    }
    #[test]
    fn be074_rejects_oversized_claim() {
        let data = vec![b'a'; MAX_CLAIM_BODY + 1];
        assert!(parse_claim(data.as_slice()).is_err());
    }
    #[test]
    fn be075_rejects_invalid_attempts_and_root() {
        for v in [0, 21] {
            let data = valid_json().replace(r#""attempt_count":1"#, &format!(r#""attempt_count":{v}"#));
            assert!(parse_claim(data.as_bytes()).is_err());
        }
        assert!(parse_claim(valid_json().replace("/lab/sample", "").as_bytes()).is_err());
    }
}
