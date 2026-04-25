//! UDP DNS server with a built-in iterative recursive resolver.
//!
//! `handle_query` reads an incoming query, hands the question to
//! [`recursive_lookup`] (which walks the DNS tree starting at a root
//! nameserver), and writes the result back to the client.

use std::net::{Ipv4Addr, UdpSocket};

use crate::bpb::BytePacketBuffer;
use crate::dns::{DNSPacket, DNSQuestion, QueryType, ResultCode};

/// `a.root-servers.net` — the bootstrap nameserver every recursive lookup
/// starts from.
const ROOT_NAMESERVER: Ipv4Addr = Ipv4Addr::new(198, 41, 0, 4);

/// A UDP DNS server bound to a single address.
pub struct DNSServer {
    socket: UdpSocket,
}

impl DNSServer {
    /// Bind a new server to `addr` (e.g. `"0.0.0.0:2053"`).
    pub fn new(addr: &str) -> Result<DNSServer, String> {
        let socket = UdpSocket::bind(addr).map_err(|e| e.to_string())?;
        Ok(DNSServer { socket })
    }

    /// Run the server forever, handling one query at a time. Errors from a
    /// single query are logged and the loop continues.
    pub fn run(&self) -> Result<(), String> {
        loop {
            if let Err(e) = self.handle_query() {
                eprintln!("error: {}", e);
            }
        }
    }

    /// Read one query from the socket, resolve it via [`recursive_lookup`],
    /// and write the response back to the client.
    fn handle_query(&self) -> Result<(), String> {
        let mut req_buffer = BytePacketBuffer::new();
        let (_, src) = self
            .socket
            .recv_from(&mut req_buffer.buf)
            .map_err(|e| e.to_string())?;

        let mut request = DNSPacket::from_buffer(&mut req_buffer)?;

        // Skeleton response: same id, server-side flags set.
        let mut packet = DNSPacket::new();
        packet.header.id = request.header.id;
        packet.header.recursion_desired = true;
        packet.header.recursion_available = true;
        packet.header.response = true;

        if let Some(question) = request.questions.pop() {
            println!("Received query: {:?}", question);

            match recursive_lookup(&question.qname, question.qtype) {
                Ok(result) => {
                    packet.questions.push(question);
                    packet.header.rescode = result.header.rescode;

                    for rec in result.answers {
                        println!("Answer: {:?}", rec);
                        packet.answers.push(rec);
                    }
                    for rec in result.authorities {
                        println!("Authority: {:?}", rec);
                        packet.authorities.push(rec);
                    }
                    for rec in result.resources {
                        println!("Resource: {:?}", rec);
                        packet.resources.push(rec);
                    }
                }
                Err(_) => {
                    packet.header.rescode = ResultCode::SERVFAIL;
                }
            }
        } else {
            // Malformed: a query with zero questions.
            packet.header.rescode = ResultCode::FORMERR;
        }

        let mut res_buffer = BytePacketBuffer::new();
        packet.write(&mut res_buffer)?;

        let len = res_buffer.pos;
        self.socket
            .send_to(&res_buffer.buf[0..len], src)
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}

/// Send a single non-recursive query for `(qname, qtype)` to `server` and
/// return the parsed response.
pub fn lookup(
    qname: &str,
    qtype: QueryType,
    server: (Ipv4Addr, u16),
) -> Result<DNSPacket, String> {
    // Port 0 -> OS-assigned ephemeral port; avoids collisions across calls.
    let socket = UdpSocket::bind(("0.0.0.0", 0)).map_err(|e| e.to_string())?;

    let mut packet = DNSPacket::new();
    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DNSQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;
    socket
        .send_to(&req_buffer.buf[0..req_buffer.pos], server)
        .map_err(|e| e.to_string())?;

    let mut res_buffer = BytePacketBuffer::new();
    socket
        .recv_from(&mut res_buffer.buf)
        .map_err(|e| e.to_string())?;

    DNSPacket::from_buffer(&mut res_buffer)
}

/// Iteratively resolve `(qname, qtype)` starting from a root nameserver.
///
/// At each step we query the current `ns`. If we get answers, we are done.
/// If we get `NXDOMAIN`, we propagate it. Otherwise we either follow a glue
/// record from the additional section, or recursively resolve an NS host
/// name and continue from its IP.
pub fn recursive_lookup(qname: &str, qtype: QueryType) -> Result<DNSPacket, String> {
    let mut ns = ROOT_NAMESERVER;

    loop {
        println!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

        let response = lookup(qname, qtype, (ns, 53))?;

        // Got answers and no error -> we're done.
        if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
            return Ok(response);
        }

        // Authoritative "no such name" -> propagate.
        if response.header.rescode == ResultCode::NXDOMAIN {
            return Ok(response);
        }

        // Try to follow a glue record (NS + matching A in additional).
        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns;
            continue;
        }

        // No glue. Find an NS host name to resolve, or give up with the last
        // response we got from the previous server.
        let new_ns_name = match response.get_unresolved_ns(qname) {
            Some(x) => x,
            None => return Ok(response),
        };

        // Recurse: resolve the NS host to an A record, then keep going.
        let recursive_response = recursive_lookup(new_ns_name, QueryType::A)?;

        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns;
        } else {
            return Ok(response);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_binds_to_ephemeral_port() {
        let server = DNSServer::new("127.0.0.1:0").expect("bind should succeed");
        let local = server.socket.local_addr().expect("local_addr");
        assert!(local.port() > 0);
    }

    #[test]
    fn new_rejects_invalid_address() {
        assert!(DNSServer::new("not a real address").is_err());
    }

    #[test]
    fn handle_query_responds_with_formerr_for_zero_question_packet() {
        let server = DNSServer::new("127.0.0.1:0").expect("bind server");
        let server_addr = server.socket.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").expect("bind client");
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();

        let mut packet = DNSPacket::new();
        packet.header.id = 0x1234;
        let mut buf = BytePacketBuffer::new();
        packet.write(&mut buf).unwrap();
        client.send_to(&buf.buf[0..buf.pos], server_addr).unwrap();

        server.handle_query().expect("handle_query");

        let mut recv = [0u8; 512];
        let (n, _) = client.recv_from(&mut recv).expect("recv response");
        let mut rbuf = BytePacketBuffer::new();
        rbuf.buf[..n].copy_from_slice(&recv[..n]);
        let response = DNSPacket::from_buffer(&mut rbuf).unwrap();

        assert_eq!(response.header.id, 0x1234);
        assert!(response.header.response);
        assert_eq!(response.header.rescode, ResultCode::FORMERR);
    }
}
