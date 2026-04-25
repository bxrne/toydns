use std::net::Ipv4Addr;

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
}

impl DNSRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DNSRecord, String> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8,
                );

                Ok(DNSRecord::A { domain, addr, ttl })
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

    pub fn write(&self, buf: &mut BytePacketBuffer) -> Result<(), String> {
        match *self {
            DNSRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buf.write_qname(domain)?;
                buf.write_u16(QueryType::A.to_num())?;
                buf.write_u16(1)?; // class IN
                buf.write_u32(ttl)?;
                buf.write_u16(4)?; // data length
                let octets = addr.octets();
                for octet in &octets {
                    buf.write_u8(*octet)?;
                }
            }
            DNSRecord::UNKNOWN {
                ref domain,
                qtype,
                data_len,
                ttl,
            } => {
                buf.write_qname(domain)?;
                buf.write_u16(qtype)?;
                buf.write_u16(1)?; // class IN
                buf.write_u32(ttl)?;
                buf.write_u16(data_len)?;

                // For UNKNOWN records, we don't have actual data to write, so we can just write zeros or skip writing the data.
                for _ in 0..data_len {
                    buf.write_u8(0)?;
                }
            }
        }

        Ok(())
    }
}
