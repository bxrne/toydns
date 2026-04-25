use crate::bpb::BytePacketBuffer;

/// ipv4 address structure
use std::net::Ipv4Addr;

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
}

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
        Ok(())
    }
}

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

                Ok(DNSRecord::A {
                    domain: domain,
                    addr: addr,
                    ttl: ttl,
                })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;

                Ok(DNSRecord::UNKNOWN {
                    domain: domain,
                    qtype: qtype_num,
                    data_len: data_len,
                    ttl: ttl,
                })
            }
        }
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

#[derive(Clone, Debug)]
pub struct DNSHeader {
    pub id: u16, // 16 bits

    pub z: bool,
    pub recursion_available: bool,
    pub recursion_desired: bool,
    pub questions: u16,
    pub answers: u16,
    pub authoritative_entries: u16,
    pub resource_entries: u16,
    pub truncated_message: bool,
    pub authoritative_answer: bool,
    pub opcode: u8,
    pub response: bool,

    pub rescode: ResultCode, // 4 bits
    pub checking_disabled: bool,
    pub authed_data: bool,
}

impl DNSHeader {
    pub fn new() -> DNSHeader {
        DNSHeader {
            id: 0,
            z: false,
            recursion_available: false,
            recursion_desired: false,
            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,
            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
        }
    }

    pub fn read(&mut self, buf: &mut BytePacketBuffer) -> Result<(), String> {
        self.id = buf.read_u16()?;

        let flags = buf.read_u16()?;
        self.z = (flags & 0x8000) > 0;
        self.recursion_available = (flags & 0x4000) > 0;
        self.recursion_desired = (flags & 0x2000) > 0;
        self.truncated_message = (flags & 0x1000) > 0;
        self.authoritative_answer = (flags & 0x0400) > 0;
        self.opcode = ((flags >> 11) & 0xF) as u8;
        self.response = (flags & 0x800) > 0;

        self.rescode = ResultCode::from_num((flags & 0xF) as u8);
        self.checking_disabled = (flags & 0x10) > 0;
        self.authed_data = (flags & 0x20) > 0;

        self.questions = buf.read_u16()?;
        self.answers = buf.read_u16()?;
        self.authoritative_entries = buf.read_u16()?;
        self.resource_entries = buf.read_u16()?;

        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            0 => ResultCode::NOERROR,
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            _ => panic!("Invalid result code"),
        }
    }
}
