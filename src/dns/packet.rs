use std::net::Ipv4Addr;

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

    /// Pick the first A record from the answers section, if any. Useful when
    /// a name resolves to several IPs and any one of them will do.
    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        self.answers.iter().find_map(|record| match record {
            DNSRecord::A { addr, .. } => Some(*addr),
            _ => None,
        })
    }

    /// Iterate over `(domain, host)` pairs for every NS record in the
    /// authorities section whose `domain` is a parent zone of `qname`.
    fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities
            .iter()
            .filter_map(|record| match record {
                DNSRecord::NS { domain, host, .. } => Some((domain.as_str(), host.as_str())),
                _ => None,
            })
            .filter(move |(domain, _)| qname.ends_with(*domain))
    }

    /// Find an NS for `qname` that has a matching glue A record in the
    /// additional/resources section and return its IP.
    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        self.get_ns(qname)
            .flat_map(|(_, host)| {
                self.resources.iter().filter_map(move |record| match record {
                    DNSRecord::A { domain, addr, .. } if domain == host => Some(*addr),
                    _ => None,
                })
            })
            .next()
    }

    /// Return the hostname of the first NS for `qname`, regardless of whether
    /// a glue record was provided. Used when we need to recursively resolve
    /// the NS host ourselves.
    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        self.get_ns(qname).map(|(_, host)| host).next()
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

    #[test]
    fn get_random_a_returns_first_a_record() {
        let mut p = DNSPacket::new();
        p.answers.push(DNSRecord::CNAME {
            domain: "x".into(),
            host: "y".into(),
            ttl: 1,
        });
        p.answers.push(DNSRecord::A {
            domain: "x".into(),
            addr: Ipv4Addr::new(1, 2, 3, 4),
            ttl: 1,
        });
        assert_eq!(p.get_random_a(), Some(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn get_random_a_none_when_no_a_records() {
        let p = DNSPacket::new();
        assert_eq!(p.get_random_a(), None);
    }

    #[test]
    fn get_resolved_ns_returns_glue_a_record_for_ns() {
        let mut p = DNSPacket::new();
        p.authorities.push(DNSRecord::NS {
            domain: "com".into(),
            host: "a.gtld-servers.net".into(),
            ttl: 1,
        });
        p.resources.push(DNSRecord::A {
            domain: "a.gtld-servers.net".into(),
            addr: Ipv4Addr::new(192, 5, 6, 30),
            ttl: 1,
        });
        assert_eq!(
            p.get_resolved_ns("example.com"),
            Some(Ipv4Addr::new(192, 5, 6, 30))
        );
    }

    #[test]
    fn get_resolved_ns_none_without_matching_glue() {
        let mut p = DNSPacket::new();
        p.authorities.push(DNSRecord::NS {
            domain: "com".into(),
            host: "a.gtld-servers.net".into(),
            ttl: 1,
        });
        assert_eq!(p.get_resolved_ns("example.com"), None);
    }

    #[test]
    fn get_unresolved_ns_returns_first_ns_host() {
        let mut p = DNSPacket::new();
        p.authorities.push(DNSRecord::NS {
            domain: "com".into(),
            host: "a.gtld-servers.net".into(),
            ttl: 1,
        });
        assert_eq!(
            p.get_unresolved_ns("example.com"),
            Some("a.gtld-servers.net")
        );
    }

    #[test]
    fn get_ns_filters_by_zone_suffix() {
        // An NS for "org" should not match a "example.com" qname.
        let mut p = DNSPacket::new();
        p.authorities.push(DNSRecord::NS {
            domain: "org".into(),
            host: "a.org-ns.net".into(),
            ttl: 1,
        });
        assert_eq!(p.get_unresolved_ns("example.com"), None);
        assert_eq!(p.get_resolved_ns("example.com"), None);
    }
}
