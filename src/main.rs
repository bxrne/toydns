//! toydns — a tiny forwarding DNS server.
//!
//! Binds UDP `0.0.0.0:2053`, parses incoming queries, forwards each one to
//! Google's public resolver (`8.8.8.8:53`), and writes the response back to
//! the original client.

mod bpb;
mod dns;
mod server;

use std::error::Error;

use server::DNSServer;

fn main() -> Result<(), Box<dyn Error>> {
    let server = DNSServer::new("0.0.0.0:2053")?;
    println!("toydns listening on 0.0.0.0:2053");
    server.run()?;
    Ok(())
}
