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
    A, // 1
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            _ => QueryType::UNKNOWN(num),
        }
    }
}
