use crate::bpb::BytePacketBuffer;

use super::header::DNSHeader;
use super::question::{DNSQuestion, QueryType};
use super::record::DNSRecord;

#[derive(Clone, Debug)]
pub struct DNSPacket {
    pub header: DNSHeader,
    pub questions: Vec<DNSQuestion>,
    pub answers: Vec<DNSRecord>,
    pub authorities: Vec<DNSRecord>,
    pub resources: Vec<DNSRecord>,
}

impl DNSPacket {
    pub fn new() -> DNSPacket {
        DNSPacket {
            header: DNSHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DNSPacket, String> {
        let mut result = DNSPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DNSQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = DNSRecord::read(buffer)?;
            result.answers.push(rec);
        }
        for _ in 0..result.header.authoritative_entries {
            let rec = DNSRecord::read(buffer)?;
            result.authorities.push(rec);
        }
        for _ in 0..result.header.resource_entries {
            let rec = DNSRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    pub fn write(&self, buf: &mut BytePacketBuffer) -> Result<(), String> {
        self.header.write(buf)?;

        for question in &self.questions {
            question.write(buf)?;
        }

        for rec in &self.answers {
            rec.write(buf)?;
        }
        for rec in &self.authorities {
            rec.write(buf)?;
        }
        for rec in &self.resources {
            rec.write(buf)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn new_packet_is_empty() {
        let p = DNSPacket::new();
        assert_eq!(p.header.id, 0);
        assert!(p.questions.is_empty());
        assert!(p.answers.is_empty());
        assert!(p.authorities.is_empty());
        assert!(p.resources.is_empty());
    }

    #[test]
    fn write_then_from_buffer_roundtrip() {
        let mut original = DNSPacket::new();
        original.header.id = 0xBEEF;
        original.header.recursion_desired = true;
        original.header.response = true;
        original.header.questions = 1;
        original.header.answers = 1;

        original
            .questions
            .push(DNSQuestion::new("example.com".to_string(), QueryType::A));
        original.answers.push(DNSRecord::A {
            domain: "example.com".to_string(),
            addr: Ipv4Addr::new(93, 184, 216, 34),
            ttl: 3600,
        });

        let mut buf = crate::bpb::BytePacketBuffer::new();
        original.write(&mut buf).unwrap();
        buf.seek(0).unwrap();

        let parsed = DNSPacket::from_buffer(&mut buf).unwrap();
        assert_eq!(parsed.header.id, original.header.id);
        assert_eq!(parsed.questions, original.questions);
        assert_eq!(parsed.answers, original.answers);
    }
}
