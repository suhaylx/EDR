// External acceptance probe; source modules below are unmodified candidate bytes.
#[path = "../clamav.rs"] mod clamav;
#[path = "../scan_jobs.rs"] mod scan_jobs;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;
fn scan(address: SocketAddr, name: &str) -> std::io::Result<clamav::Verdict> {
    let mut connection = TcpStream::connect_timeout(&address, Duration::from_secs(3))?;
    connection.set_read_timeout(Some(Duration::from_secs(20)))?;
    connection.set_write_timeout(Some(Duration::from_secs(20)))?;
    let mut source = File::open(name)?;
    clamav::scan_stream(&mut connection, &mut source, 1024 * 1024)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 { return Err("expected local port, benign fixture and exact EICAR fixture".into()); }
    let port: u16 = args[1].parse()?;
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let benign = scan(address, &args[2])?;
    let eicar = scan(address, &args[3])?;
    assert_eq!(benign, clamav::Verdict::CleanBySignature);
    assert_eq!(eicar, clamav::Verdict::Malicious("Eicar-Test-Signature".into()));
    println!("{{\"benign\":\"clean_by_signature\",\"eicar\":\"malicious\",\"signature\":\"Eicar-Test-Signature\",\"transport\":\"loopback_tcp_probe\"}}");
    Ok(())
}
