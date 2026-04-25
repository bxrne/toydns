//! UDP DNS server that forwards queries to an upstream recursive resolver.
//!
//! The server reads a query from the socket, builds a response packet that
//! mirrors the request id and sets the standard response/recursion flags,
//! delegates the actual resolution to [`lookup`], copies the answer/authority
//! /additional sections back into the response, and writes it to the client.

use std::net::UdpSocket;

use crate::bpb::BytePacketBuffer;
use crate::dns::{DNSPacket, DNSQuestion, QueryType, ResultCode};

/// Upstream recursive resolver used by [`lookup`].
const UPSTREAM: (&str, u16) = ("8.8.8.8", 53);

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

    /// Read one query from the socket, resolve it via [`lookup`], and write
    /// the response back to the client.
    fn handle_query(&self) -> Result<(), String> {
        // Receive the raw query bytes directly into a BytePacketBuffer.
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

        // We only handle a single question per packet, which is the
        // overwhelmingly common case in practice.
        if let Some(question) = request.questions.pop() {
            println!("Received query: {:?}", question);

            match lookup(&question.qname, question.qtype) {
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

        // Serialize and ship.
        let mut res_buffer = BytePacketBuffer::new();
        packet.write(&mut res_buffer)?;

        let len = res_buffer.pos;
        let data = &res_buffer.buf[0..len];
        self.socket.send_to(data, src).map_err(|e| e.to_string())?;

        Ok(())
    }
}

/// Forward a single question to [`UPSTREAM`] and return the parsed response.
///
/// Binds an ephemeral UDP socket, sends a recursion-desired query for
/// `(qname, qtype)`, waits for the reply, and parses it into a [`DNSPacket`].
pub fn lookup(qname: &str, qtype: QueryType) -> Result<DNSPacket, String> {
    // Port 0 lets the OS pick a free ephemeral port; this avoids collisions
    // when multiple lookups run back-to-back.
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
        .send_to(&req_buffer.buf[0..req_buffer.pos], UPSTREAM)
        .map_err(|e| e.to_string())?;

    let mut res_buffer = BytePacketBuffer::new();
    socket
        .recv_from(&mut res_buffer.buf)
        .map_err(|e| e.to_string())?;

    DNSPacket::from_buffer(&mut res_buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_binds_to_ephemeral_port() {
        // Port 0 -> OS-assigned free port. Verifies the constructor wires up
        // the socket without requiring a fixed port to be free on the host.
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
        // Spin up a server on an ephemeral port and a client socket.
        let server = DNSServer::new("127.0.0.1:0").expect("bind server");
        let server_addr = server.socket.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").expect("bind client");
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();

        // Build a header-only packet (no questions). handle_query should
        // short-circuit to FORMERR without touching the network.
        let mut packet = DNSPacket::new();
        packet.header.id = 0x1234;
        let mut buf = BytePacketBuffer::new();
        packet.write(&mut buf).unwrap();
        client
            .send_to(&buf.buf[0..buf.pos], server_addr)
            .unwrap();

        // Run one iteration of the server loop on this thread.
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
