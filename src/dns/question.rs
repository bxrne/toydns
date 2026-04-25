use anyhow::Result;

use crate::bpb::BytePacketBuffer;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DNSQuestion {
    pub qname: String,
    pub qtype: QueryType,
}

impl DNSQuestion {
    pub fn new(qname: String, qtype: QueryType) -> Self {
        Self { qname, qtype }
    }

    pub fn read(&mut self, buf: &mut BytePacketBuffer) -> Result<()> {
        buf.read_qname(&mut self.qname)?;
        self.qtype = QueryType::from_num(buf.read_u16()?);
        let _ = buf.read_u16()?;
        Ok(())
    }

    pub fn write(&self, buf: &mut BytePacketBuffer) -> Result<()> {
        buf.write_qname(&self.qname)?;
        buf.write_u16(self.qtype.to_num())?;
        buf.write_u16(1)
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,
    NS,
    CNAME,
    MX,
    AAAA,
}

impl QueryType {
    pub fn to_num(self) -> u16 {
        match self {
            Self::UNKNOWN(x) => x,
            Self::A => 1,
            Self::NS => 2,
            Self::CNAME => 5,
            Self::MX => 15,
            Self::AAAA => 28,
        }
    }

    pub fn from_num(num: u16) -> Self {
        match num {
            1 => Self::A,
            2 => Self::NS,
            5 => Self::CNAME,
            15 => Self::MX,
            28 => Self::AAAA,
            _ => Self::UNKNOWN(num),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpb::BytePacketBuffer;

    #[test]
    fn query_type_roundtrip_known() {
        for qt in [
            QueryType::A,
            QueryType::NS,
            QueryType::CNAME,
            QueryType::MX,
            QueryType::AAAA,
        ] {
            assert_eq!(QueryType::from_num(qt.to_num()), qt);
        }
    }

    #[test]
    fn query_type_unknown_passes_value_through() {
        let qt = QueryType::from_num(999);
        assert_eq!(qt, QueryType::UNKNOWN(999));
        assert_eq!(qt.to_num(), 999);
    }

    #[test]
    fn write_then_read_roundtrip() {
        let original = DNSQuestion::new("foo.example.com".to_owned(), QueryType::AAAA);
        let mut buf = BytePacketBuffer::new();
        original.write(&mut buf).unwrap();
        buf.seek(0).unwrap();

        let mut read_back = DNSQuestion::new(String::new(), QueryType::UNKNOWN(0));
        read_back.read(&mut buf).unwrap();
        assert_eq!(read_back, original);
    }

    #[test]
    fn write_consumes_qname_qtype_class() {
        let q = DNSQuestion::new("a.b".to_owned(), QueryType::A);
        let mut buf = BytePacketBuffer::new();
        q.write(&mut buf).unwrap();
        assert_eq!(buf.pos, 9);
    }
}
