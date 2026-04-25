use crate::bpb::BytePacketBuffer;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DNSQuestion {
    qname: String,    // Domain name in DNS format
    qtype: QueryType, // Type of the query (e.g., A, AAAA, CNAME)
}

impl DNSQuestion {
    pub fn new(qname: String, qtype: QueryType) -> DNSQuestion {
        DNSQuestion { qname, qtype }
    }

    pub fn read(&mut self, buf: &mut BytePacketBuffer) -> Result<(), String> {
        buf.read_qname(&mut self.qname)?;

        self.qtype = QueryType::from_num(buf.read_u16()?);
        let _ = buf.read_u16()?; // class
        Ok(())
    }

    pub fn write(&self, buf: &mut BytePacketBuffer) -> Result<(), String> {
        buf.write_qname(&self.qname)?;
        buf.write_u16(self.qtype.to_num())?;
        buf.write_u16(1)?; // class IN
        Ok(())
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,     // 1
    NS,    // 2
    CNAME, // 5
    MX,    // 15
    AAAA,  // 28
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpb::BytePacketBuffer;

    #[test]
    fn query_type_roundtrip_known() {
        for qt in [QueryType::A, QueryType::NS, QueryType::CNAME, QueryType::MX, QueryType::AAAA] {
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
        let original = DNSQuestion::new("foo.example.com".to_string(), QueryType::AAAA);
        let mut buf = BytePacketBuffer::new();
        original.write(&mut buf).unwrap();
        buf.seek(0).unwrap();

        let mut read_back = DNSQuestion::new(String::new(), QueryType::UNKNOWN(0));
        read_back.read(&mut buf).unwrap();
        assert_eq!(read_back, original);
    }

    #[test]
    fn write_consumes_qname_qtype_class() {
        let q = DNSQuestion::new("a.b".to_string(), QueryType::A);
        let mut buf = BytePacketBuffer::new();
        q.write(&mut buf).unwrap();
        // qname "a.b" = 1,'a',1,'b',0 = 5 bytes; plus 2 (qtype) + 2 (class) = 9
        assert_eq!(buf.pos, 9);
    }
}
