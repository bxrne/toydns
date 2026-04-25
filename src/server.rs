//! UDP DNS server with a built-in iterative recursive resolver.

use anyhow::{Context, Result};
use std::net::{Ipv4Addr, UdpSocket};

use crate::bpb::BytePacketBuffer;
use crate::dns::{DNSPacket, DNSQuestion, QueryType, ResultCode};

const ROOT_NAMESERVER: Ipv4Addr = Ipv4Addr::new(198, 41, 0, 4);

pub struct DNSServer {
    socket: UdpSocket,
}

impl DNSServer {
    pub fn new(addr: &str) -> Result<Self> {
        let socket = UdpSocket::bind(addr).with_context(|| format!("failed to bind {addr}"))?;
        Ok(Self { socket })
    }

    pub fn run(&self) -> Result<()> {
        loop {
            if let Err(e) = self.handle_query() {
                eprintln!("error: {e:#}");
            }
        }
    }

    fn handle_query(&self) -> Result<()> {
        let mut req_buffer = BytePacketBuffer::new();
        let (_, src) = self
            .socket
            .recv_from(&mut req_buffer.buf)
            .context("failed receiving udp query")?;

        let mut request = DNSPacket::from_buffer(&mut req_buffer)?;
        let mut packet = DNSPacket::new();
        packet.header.id = request.header.id;
        packet.header.recursion_desired = true;
        packet.header.recursion_available = true;
        packet.header.response = true;

        let Some(question) = request.questions.pop() else {
            packet.header.rescode = ResultCode::FORMERR;
            return self.send_response(src, packet);
        };

        println!("Received query: {question:?}");

        match recursive_lookup(&question.qname, question.qtype) {
            Ok(result) => {
                packet.questions.push(question);
                packet.header.rescode = result.header.rescode;
                log_and_append("Answer", result.answers, &mut packet.answers);
                log_and_append("Authority", result.authorities, &mut packet.authorities);
                log_and_append("Resource", result.resources, &mut packet.resources);
            }
            Err(_) => packet.header.rescode = ResultCode::SERVFAIL,
        }

        self.send_response(src, packet)
    }

    fn send_response(&self, src: std::net::SocketAddr, packet: DNSPacket) -> Result<()> {
        let mut res_buffer = BytePacketBuffer::new();
        packet.write(&mut res_buffer)?;
        self.socket
            .send_to(&res_buffer.buf[..res_buffer.pos], src)
            .context("failed sending udp response")?;
        Ok(())
    }
}

fn log_and_append(
    label: &str,
    records: Vec<crate::dns::DNSRecord>,
    out: &mut Vec<crate::dns::DNSRecord>,
) {
    for rec in records {
        println!("{label}: {rec:?}");
        out.push(rec);
    }
}

pub fn lookup(qname: &str, qtype: QueryType, server: (Ipv4Addr, u16)) -> Result<DNSPacket> {
    let socket = UdpSocket::bind(("0.0.0.0", 0)).context("failed binding ephemeral udp socket")?;

    let mut packet = DNSPacket::new();
    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DNSQuestion::new(qname.to_owned(), qtype));

    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;
    socket
        .send_to(&req_buffer.buf[..req_buffer.pos], server)
        .with_context(|| format!("failed sending query to {server:?}"))?;

    let mut res_buffer = BytePacketBuffer::new();
    socket
        .recv_from(&mut res_buffer.buf)
        .context("failed receiving upstream response")?;

    DNSPacket::from_buffer(&mut res_buffer)
}

pub fn recursive_lookup(qname: &str, qtype: QueryType) -> Result<DNSPacket> {
    let mut ns = ROOT_NAMESERVER;

    loop {
        println!("attempting lookup of {qtype:?} {qname} with ns {ns}");
        let response = lookup(qname, qtype, (ns, 53))?;

        if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
            return Ok(response);
        }

        if response.header.rescode == ResultCode::NXDOMAIN {
            return Ok(response);
        }

        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns;
            continue;
        }

        let Some(new_ns_name) = response.get_unresolved_ns(qname) else {
            return Ok(response);
        };

        let recursive_response = recursive_lookup(new_ns_name, QueryType::A)?;
        let Some(new_ns) = recursive_response.get_random_a() else {
            return Ok(response);
        };

        ns = new_ns;
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
        client.send_to(&buf.buf[..buf.pos], server_addr).unwrap();

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
