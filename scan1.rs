use std::net::{IpAddr, TcpStream};
use std::io::{self, Write};
use std::time::Duration;

fn check_vulnerability(address: &str, port: u16) -> io::Result<bool> {
    let socket_address = format!("{}:{}", address, port);
    let ip_address: IpAddr = address.parse()?;
    let mut stream = TcpStream::connect_timeout(&socket_address.parse()?, Duration::from_secs(5))?;
    stream.write_all(b"GET / HTTP/1.1\r\n\r\n")?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    if response.contains("vulnerable") {
        return Ok(true);
    }
    Ok(false)
}

fn main() -> io::Result<()> {
    let address = "127.0.0.1";
    let ports = vec![22, 80, 443, 8080];
    for port in ports {
        match check_vulnerability(address, port) {
            Ok(true) => println!("Port {} is vulnerable.", port),
            Ok(false) => println!("Port {} is not vulnerable.", port),
            Err(_) => println!("Error connecting to port {}.", port),
        }
    }
    Ok(())
}
