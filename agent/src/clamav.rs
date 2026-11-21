//! Local clamd INSTREAM protocol adapter for the single TuranSec endpoint agent.
//!
//! This is not an antivirus engine: it requires a separately installed, healthy
//! ClamAV daemon with genuine signature databases. The caller must authorize a
//! scan target before opening it and enforce policy-driven scan limits.
use std::io::{self, Read, Write};

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    CleanBySignature,
    Malicious(String),
    ScannerError(String),
}

fn parse_reply(bytes: &[u8]) -> io::Result<Verdict> {
    if bytes.len() > 2048 || bytes.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid clamd frame"));
    }
    let msg = std::str::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid clamd reply encoding"))?;
    let result = msg.strip_prefix("stream: ")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unexpected clamd response"))?;
    if result == "OK" {
        Ok(Verdict::CleanBySignature) // signature absence is NOT proof of safety
    } else if let Some(sig) = result.strip_suffix(" FOUND") {
        if sig.is_empty() || sig.len() > 256 || sig.chars().any(char::is_control) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid clamd signature name"));
        }
        Ok(Verdict::Malicious(sig.to_owned()))
    } else if let Some(error) = result.strip_suffix(" ERROR") {
        if error.is_empty() || error.len() > 1024 || error.chars().any(char::is_control) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid clamd error text"));
        }
        Ok(Verdict::ScannerError(error.to_owned()))
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, "unknown clamd verdict"))
    }
}

/// Stream a bounded file to a *local, trusted* clamd endpoint.
/// A successful connection does not establish device identity or agent policy.
/// Do not expose clamd's plaintext protocol to an untrusted network.
pub fn scan_stream<S: Read + Write, R: Read>(
    connection: &mut S,
    source: &mut R,
    max_bytes: u64,
) -> io::Result<Verdict> {
    if max_bytes == 0 || max_bytes > 1024 * 1024 * 1024 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid scan size cap"));
    }
    connection.write_all(b"zINSTREAM\0")?;
    let mut buf = [0u8; 8192];
    let mut total = 0u64;
    loop {
        let size = source.read(&mut buf)?;
        if size == 0 { break; }
        total = total.checked_add(size as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "scan size overflow"))?;
        if total > max_bytes {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "scan size limit exceeded"));
        }
        connection.write_all(&(size as u32).to_be_bytes())?;
        connection.write_all(&buf[..size])?;
    }
    connection.write_all(&0u32.to_be_bytes())?;
    connection.flush()?;
    let mut reply = Vec::with_capacity(128);
    loop {
        if reply.len() >= 2048 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "oversized clamd reply"));
        }
        let mut byte = [0u8; 1];
        connection.read_exact(&mut byte)?;
        if byte[0] == 0 { break; }
        reply.push(byte[0]);
    }
    parse_reply(&reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct Stub {
        response: Cursor<Vec<u8>>,
        sent: Vec<u8>,
    }
    impl Read for Stub {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> { self.response.read(out) }
    }
    impl Write for Stub {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.sent.extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }
    fn stub(response: &[u8]) -> Stub {
        Stub { response: Cursor::new(response.to_vec()), sent: Vec::new() }
    }

    #[test]
    fn streams_nul_framed_payload_and_clean_only_by_signature() {
        let mut conn = stub(b"stream: OK\0");
        let verdict = scan_stream(&mut conn, &mut Cursor::new(b"abc"), 64).unwrap();
        assert_eq!(verdict, Verdict::CleanBySignature);
        assert_eq!(conn.sent, b"zINSTREAM\0\0\0\0\x03abc\0\0\0\0");
    }
    #[test]
    fn recognizes_detection_and_error_separately() {
        let mut conn = stub(b"stream: Eicar-Test-Signature FOUND\0");
        assert_eq!(scan_stream(&mut conn, &mut Cursor::new(b"x"), 4).unwrap(),
            Verdict::Malicious("Eicar-Test-Signature".into()));
        let mut conn = stub(b"stream: size limit exceeded ERROR\0");
        assert_eq!(scan_stream(&mut conn, &mut Cursor::new(b"x"), 4).unwrap(),
            Verdict::ScannerError("size limit exceeded".into()));
    }
    #[test]
    fn be096_recognizes_signature_without_reporting_clean() {
        let verdict = parse_reply(b"stream: Eicar-Test-Signature FOUND").unwrap();
        assert_eq!(verdict, Verdict::Malicious("Eicar-Test-Signature".into()));
    }
    #[test]
    fn be097_rejects_control_characters_in_signature_and_error() {
        assert!(parse_reply(b"stream: injected\\rname FOUND").is_err());
        assert!(parse_reply(b"stream: internal\\nproblem ERROR").is_err());
    }
    #[test]
    fn be098_rejects_oversized_signature() {
        let reply = format!("stream: {} FOUND", "A".repeat(257));
        assert!(parse_reply(reply.as_bytes()).is_err());
    }
    #[test]
    fn be099_rejects_embedded_nul_or_empty_error() {
        assert!(parse_reply(b"stream: M\\0AL FOUND").is_err());
        assert!(parse_reply(b"stream:  ERROR").is_err());
    }
    #[test]
    fn be100_rejects_oversized_and_truncated_reply() {
        assert!(parse_reply(&vec![b'A';2049]).is_err());
        let mut conn = stub(b"stream: not_terminated");
        assert!(scan_stream(&mut conn,&mut Cursor::new(b"x"),3).is_err());
    }
    #[test]
    fn enforces_input_cap_and_rejects_unexpected_replies() {
        let mut conn = stub(b"stream: OK\0");
        assert!(scan_stream(&mut conn, &mut Cursor::new(b"abcd"), 3).is_err());
        let mut conn = stub(b"PONG\0");
        assert!(scan_stream(&mut conn, &mut Cursor::new(b"x"), 3).is_err());
    }
}
