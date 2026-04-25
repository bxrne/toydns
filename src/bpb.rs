use anyhow::{Result, bail};

const DNS_PACKET_SIZE: usize = 512;

#[derive(Clone, Debug)]
pub struct BytePacketBuffer {
    pub buf: [u8; DNS_PACKET_SIZE],
    pub pos: usize,
}

impl Default for BytePacketBuffer {
    fn default() -> Self {
        Self {
            buf: [0; DNS_PACKET_SIZE],
            pos: 0,
        }
    }
}

impl BytePacketBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    fn position(&self) -> usize {
        self.pos
    }

    fn require_index(pos: usize) -> Result<()> {
        if pos >= DNS_PACKET_SIZE {
            bail!("buffer overflow");
        }
        Ok(())
    }

    fn require_range(start: usize, len: usize) -> Result<()> {
        let end = start
            .checked_add(len)
            .ok_or_else(|| anyhow::anyhow!("buffer overflow"))?;
        if end > DNS_PACKET_SIZE {
            bail!("buffer overflow");
        }
        Ok(())
    }

    pub fn step(&mut self, steps: usize) -> Result<()> {
        self.seek(
            self.pos
                .checked_add(steps)
                .ok_or_else(|| anyhow::anyhow!("buffer overflow"))?,
        )
    }

    pub fn seek(&mut self, pos: usize) -> Result<()> {
        if pos > DNS_PACKET_SIZE {
            bail!("buffer overflow");
        }
        self.pos = pos;
        Ok(())
    }

    pub fn read(&mut self) -> Result<u8> {
        let res = self.get(self.pos)?;
        self.pos += 1;
        Ok(res)
    }

    fn get(&self, pos: usize) -> Result<u8> {
        Self::require_index(pos)?;
        Ok(self.buf[pos])
    }

    fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        Self::require_range(start, len)?;
        Ok(&self.buf[start..start + len])
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        Ok(((self.read()? as u16) << 8) | (self.read()? as u16))
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        Ok(((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | (self.read()? as u32))
    }

    pub fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        let mut pos = self.position();
        let mut jumped = false;
        let mut jumps_performed = 0;

        const MAX_JUMPS: usize = 5;

        let mut delim = "";
        loop {
            if jumps_performed > MAX_JUMPS {
                bail!("limit of {MAX_JUMPS} jumps exceeded");
            }

            let len = self.get(pos)?;

            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.seek(pos + 2)?;
                }

                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                jumped = true;
                jumps_performed += 1;
                continue;
            }

            pos += 1;

            if len == 0 {
                break;
            }

            outstr.push_str(delim);

            let label_bytes = self.get_range(pos, len as usize)?;
            let label = std::str::from_utf8(label_bytes)?;
            outstr.push_str(&label.to_lowercase());

            delim = ".";
            pos += len as usize;
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }

    pub fn write_qname(&mut self, qname: &str) -> Result<()> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 63 {
                bail!("label too long");
            }
            self.write(len as u8)?;
            for b in label.as_bytes() {
                self.write(*b)?;
            }
        }
        self.write(0)
    }

    fn write(&mut self, val: u8) -> Result<()> {
        Self::require_index(self.pos)?;
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    pub fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)
    }

    pub fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)
    }

    pub fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write((val >> 24) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write((val & 0xFF) as u8)
    }

    pub fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        Self::require_index(pos)?;
        self.buf[pos] = val;
        Ok(())
    }

    pub fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_buffer_is_zeroed_and_at_pos_zero() {
        let b = BytePacketBuffer::new();
        assert_eq!(b.pos, 0);
        assert!(b.buf.iter().all(|&x| x == 0));
    }

    #[test]
    fn step_and_seek_advance_position() {
        let mut b = BytePacketBuffer::new();
        b.step(10).unwrap();
        assert_eq!(b.position(), 10);
        b.seek(3).unwrap();
        assert_eq!(b.position(), 3);
    }

    #[test]
    fn step_overflow_errors() {
        let mut b = BytePacketBuffer::new();
        assert!(b.step(513).is_err());
    }

    #[test]
    fn seek_overflow_errors() {
        let mut b = BytePacketBuffer::new();
        assert!(b.seek(513).is_err());
    }

    #[test]
    fn write_then_read_u8_u16_u32_roundtrip() {
        let mut b = BytePacketBuffer::new();
        b.write_u8(0xAB).unwrap();
        b.write_u16(0x1234).unwrap();
        b.write_u32(0xDEADBEEF).unwrap();
        b.seek(0).unwrap();
        assert_eq!(b.read().unwrap(), 0xAB);
        assert_eq!(b.read_u16().unwrap(), 0x1234);
        assert_eq!(b.read_u32().unwrap(), 0xDEADBEEF);
    }

    #[test]
    fn read_at_end_errors() {
        let mut b = BytePacketBuffer::new();
        b.pos = DNS_PACKET_SIZE;
        assert!(b.read().is_err());
    }

    #[test]
    fn set_and_set_u16_patch_bytes() {
        let mut b = BytePacketBuffer::new();
        b.step(4).unwrap();
        b.set(0, 0x42).unwrap();
        b.set_u16(1, 0xBEEF).unwrap();
        assert_eq!(b.buf[0], 0x42);
        assert_eq!(b.buf[1], 0xBE);
        assert_eq!(b.buf[2], 0xEF);
    }

    #[test]
    fn write_qname_then_read_qname_roundtrip() {
        let mut b = BytePacketBuffer::new();
        b.write_qname("www.example.com").unwrap();
        b.seek(0).unwrap();
        let mut out = String::new();
        b.read_qname(&mut out).unwrap();
        assert_eq!(out, "www.example.com");
    }

    #[test]
    fn write_qname_rejects_long_label() {
        let mut b = BytePacketBuffer::new();
        let long = "a".repeat(64);
        assert!(b.write_qname(&long).is_err());
    }

    #[test]
    fn read_qname_follows_compression_pointer() {
        let mut b = BytePacketBuffer::new();
        b.write_qname("example.com").unwrap();
        let pointer_pos = b.pos;
        b.write_u8(0xC0).unwrap();
        b.write_u8(0x00).unwrap();
        b.seek(pointer_pos).unwrap();
        let mut out = String::new();
        b.read_qname(&mut out).unwrap();
        assert_eq!(out, "example.com");
        assert_eq!(b.pos, pointer_pos + 2);
    }
}
