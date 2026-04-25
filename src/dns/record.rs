use std::net::{Ipv4Addr, Ipv6Addr};

use crate::bpb::BytePacketBuffer;

use super::question::QueryType;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DNSRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }, // 1
    NS {
        domain: String,
        host: String,
        ttl: u32,
    }, // 2
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    }, // 5
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    }, // 15
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    }, // 28
}

impl DNSRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DNSRecord, String> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _class = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw = buffer.read_u32()?;
                let addr = Ipv4Addr::from(raw);
                Ok(DNSRecord::A { domain, addr, ttl })
            }
            QueryType::AAAA => {
                let a = buffer.read_u32()?;
                let b = buffer.read_u32()?;
                let c = buffer.read_u32()?;
                let d = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    (a >> 16) as u16, a as u16,
                    (b >> 16) as u16, b as u16,
                    (c >> 16) as u16, c as u16,
                    (d >> 16) as u16, d as u16,
                );
                Ok(DNSRecord::AAAA { domain, addr, ttl })
            }
            QueryType::NS => {
                let mut host = String::new();
                buffer.read_qname(&mut host)?;
                Ok(DNSRecord::NS { domain, host, ttl })
            }
            QueryType::CNAME => {
                let mut host = String::new();
                buffer.read_qname(&mut host)?;
                Ok(DNSRecord::CNAME { domain, host, ttl })
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut host = String::new();
                buffer.read_qname(&mut host)?;
                Ok(DNSRecord::MX { domain, priority, host, ttl })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;
                Ok(DNSRecord::UNKNOWN {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl,
                })
            }
        }
    }

    /// Write this record to `buf`. Returns the number of bytes written.
    pub fn write(&self, buf: &mut BytePacketBuffer) -> Result<usize, String> {
        let start_pos = buf.pos;

        match self {
            DNSRecord::A { domain, addr, ttl } => {
                write_preamble(buf, domain, QueryType::A, *ttl)?;
                buf.write_u16(4)?;
                for octet in addr.octets() {
                    buf.write_u8(octet)?;
                }
            }
            DNSRecord::AAAA { domain, addr, ttl } => {
                write_preamble(buf, domain, QueryType::AAAA, *ttl)?;
                buf.write_u16(16)?;
                for segment in addr.segments() {
                    buf.write_u16(segment)?;
                }
            }
            DNSRecord::NS { domain, host, ttl } => {
                write_preamble(buf, domain, QueryType::NS, *ttl)?;
                write_rdata_with_qname(buf, host)?;
            }
            DNSRecord::CNAME { domain, host, ttl } => {
                write_preamble(buf, domain, QueryType::CNAME, *ttl)?;
                write_rdata_with_qname(buf, host)?;
            }
            DNSRecord::MX { domain, priority, host, ttl } => {
                write_preamble(buf, domain, QueryType::MX, *ttl)?;
                let len_pos = buf.pos;
                buf.write_u16(0)?; // placeholder
                buf.write_u16(*priority)?;
                buf.write_qname(host)?;
                let size = buf.pos - (len_pos + 2);
                buf.set_u16(len_pos, size as u16)?;
            }
            DNSRecord::UNKNOWN { .. } => {
                println!("Skipping record: {:?}", self);
            }
        }

        Ok(buf.pos - start_pos)
    }
}

/// Writes the common record preamble: qname, type, class, ttl.
fn write_preamble(
    buf: &mut BytePacketBuffer,
    domain: &str,
    qtype: QueryType,
    ttl: u32,
) -> Result<(), String> {
    buf.write_qname(domain)?;
    buf.write_u16(qtype.to_num())?;
    buf.write_u16(1)?; // class IN
    buf.write_u32(ttl)?;
    Ok(())
}

/// Writes a 2-byte rdlength placeholder, writes a qname as rdata, then
/// back-patches the rdlength.
fn write_rdata_with_qname(buf: &mut BytePacketBuffer, host: &str) -> Result<(), String> {
    let len_pos = buf.pos;
    buf.write_u16(0)?; // placeholder
    buf.write_qname(host)?;
    let size = buf.pos - (len_pos + 2);
    buf.set_u16(len_pos, size as u16)?;
    Ok(())
}
