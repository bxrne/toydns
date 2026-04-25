use anyhow::{Result, bail};

use crate::bpb::BytePacketBuffer;

#[derive(Clone, Debug, Default)]
pub struct DNSHeader {
    pub id: u16,

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

    pub rescode: ResultCode,
    pub checking_disabled: bool,
    pub authed_data: bool,
}

impl DNSHeader {
    pub fn read(&mut self, buf: &mut BytePacketBuffer) -> Result<()> {
        self.id = buf.read_u16()?;

        let flags = buf.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::try_from(b & 0x0F)?;
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buf.read_u16()?;
        self.answers = buf.read_u16()?;
        self.authoritative_entries = buf.read_u16()?;
        self.resource_entries = buf.read_u16()?;

        Ok(())
    }

    pub fn write(&self, buf: &mut BytePacketBuffer) -> Result<()> {
        buf.write_u16(self.id)?;

        let a: u8 = (self.recursion_desired as u8)
            | ((self.truncated_message as u8) << 1)
            | ((self.authoritative_answer as u8) << 2)
            | ((self.opcode & 0x0F) << 3)
            | ((self.response as u8) << 7);

        let b: u8 = (self.rescode.to_num() & 0x0F)
            | ((self.checking_disabled as u8) << 4)
            | ((self.authed_data as u8) << 5)
            | ((self.z as u8) << 6)
            | ((self.recursion_available as u8) << 7);

        buf.write_u8(a)?;
        buf.write_u8(b)?;

        buf.write_u16(self.questions)?;
        buf.write_u16(self.answers)?;
        buf.write_u16(self.authoritative_entries)?;
        buf.write_u16(self.resource_entries)?;

        Ok(())
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum ResultCode {
    #[default]
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl TryFrom<u8> for ResultCode {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        Ok(match value {
            0 => Self::NOERROR,
            1 => Self::FORMERR,
            2 => Self::SERVFAIL,
            3 => Self::NXDOMAIN,
            4 => Self::NOTIMP,
            5 => Self::REFUSED,
            _ => bail!("invalid result code: {value}"),
        })
    }
}

impl ResultCode {
    pub fn to_num(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpb::BytePacketBuffer;

    #[test]
    fn result_code_roundtrip_all_known() {
        for n in 0u8..=5 {
            assert_eq!(ResultCode::try_from(n).unwrap().to_num(), n);
        }
    }

    #[test]
    fn result_code_invalid_errors() {
        assert!(ResultCode::try_from(99).is_err());
    }

    #[test]
    fn new_header_has_sane_defaults() {
        let h = DNSHeader::default();
        assert_eq!(h.id, 0);
        assert_eq!(h.questions, 0);
        assert_eq!(h.rescode, ResultCode::NOERROR);
        assert!(!h.response);
    }

    #[test]
    fn write_then_read_roundtrip() {
        let mut original = DNSHeader::default();
        original.id = 6666;
        original.recursion_desired = true;
        original.recursion_available = true;
        original.response = true;
        original.opcode = 0;
        original.rescode = ResultCode::NXDOMAIN;
        original.questions = 1;
        original.answers = 2;
        original.authoritative_entries = 3;
        original.resource_entries = 4;
        original.authoritative_answer = true;
        original.truncated_message = true;
        original.checking_disabled = true;
        original.authed_data = true;
        original.z = true;

        let mut buf = BytePacketBuffer::new();
        original.write(&mut buf).unwrap();
        buf.seek(0).unwrap();

        let mut read_back = DNSHeader::default();
        read_back.read(&mut buf).unwrap();

        assert_eq!(read_back.id, original.id);
        assert_eq!(read_back.recursion_desired, original.recursion_desired);
        assert_eq!(read_back.recursion_available, original.recursion_available);
        assert_eq!(read_back.response, original.response);
        assert_eq!(read_back.opcode, original.opcode);
        assert_eq!(read_back.rescode, original.rescode);
        assert_eq!(read_back.questions, original.questions);
        assert_eq!(read_back.answers, original.answers);
        assert_eq!(
            read_back.authoritative_entries,
            original.authoritative_entries
        );
        assert_eq!(read_back.resource_entries, original.resource_entries);
        assert_eq!(
            read_back.authoritative_answer,
            original.authoritative_answer
        );
        assert_eq!(read_back.truncated_message, original.truncated_message);
        assert_eq!(read_back.checking_disabled, original.checking_disabled);
        assert_eq!(read_back.authed_data, original.authed_data);
        assert_eq!(read_back.z, original.z);
    }
}
