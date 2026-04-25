pub struct BytePacketBuffer {
    pub buf: [u8; 512], // DNS messages are typically limited to 512 bytes
    pub pos: usize,     // Current position in the buffer
}

impl BytePacketBuffer {
    /// Creates a new BytePacketBuffer with an empty buffer and position set to 0.
    pub fn new() -> Self {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    /// Returns the current position in the buffer.
    fn position(&self) -> usize {
        self.pos
    }

    /// Advances the current position by a specified number of steps.
    pub fn step(&mut self, steps: usize) -> Result<(), String> {
        self.pos += steps;
        if self.pos > 512 {
            return Err("Buffer overflow".to_string());
        }
        Ok(())
    }

    /// change the current position to a specified position.
    pub fn seek(&mut self, pos: usize) -> Result<(), String> {
        if pos > 512 {
            return Err("Buffer overflow".to_string());
        }
        self.pos = pos;
        Ok(())
    }

    /// read a byte then move pos ahead
    pub fn read(&mut self) -> Result<u8, String> {
        if self.pos >= 512 {
            return Err("Buffer overflow".to_string());
        }
        let res = self.buf[self.pos];
        self.pos += 1;
        Ok(res)
    }

    /// get a single byte, leaving pos untouched
    fn get(&self, pos: usize) -> Result<u8, String> {
        if self.pos > 512 {
            return Err("Buffer overflow".to_string());
        }

        Ok(self.buf[pos])
    }

    /// get a range of bytes, leaving pos untouched
    fn get_range(&self, start: usize, len: usize) -> Result<&[u8], String> {
        if start + len > 512 {
            return Err("Buffer overflow".to_string());
        }

        Ok(&self.buf[start..start + len])
    }

    /// read two bytes and move pos ahead the same
    pub fn read_u16(&mut self) -> Result<u16, String> {
        Ok(((self.read()? as u16) << 8) | (self.read()? as u16)) // bitwise OR to combine the two bytes into a single u16 value
    }

    /// read four bytes and move pos ahead the same
    pub fn read_u32(&mut self) -> Result<u32, String> {
        Ok(((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | (self.read()? as u32)) // bitwise OR to combine the four bytes into a single u32 value
    }

    /// read qname (dns domain name)
    pub fn read_qname(&mut self, outstr: &mut String) -> Result<(), String> {
        // Track our position locally; pointers must NOT mutate the buffer
        // position past the original 2-byte pointer.
        let mut pos = self.position();

        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        let mut delim = "";
        loop {
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps));
            }

            let len = self.get(pos)?;

            // Check for pointer (compression)
            if (len & 0xC0) == 0xC0 {
                // On the first jump, advance the buffer position past the
                // 2-byte pointer.
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
            let label = std::str::from_utf8(label_bytes)
                .map_err(|_| "Invalid UTF-8 in label".to_string())?;
            outstr.push_str(&label.to_lowercase());

            delim = ".";

            pos += len as usize;
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }

    /// write a qname (dns domain name) to the buffer
    pub fn write_qname(&mut self, qname: &str) -> Result<(), String> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 63 {
                return Err("Label too long".to_string());
            }
            self.write(len as u8)?; // Write the length of the label
            for b in label.as_bytes() {
                self.write(*b)?; // Write the label bytes
            }
        }
        self.write(0)?; // Write the null byte to indicate the end of the domain name
        Ok(())
    }

    /// write a byte to the buffer and move pos ahead
    fn write(&mut self, val: u8) -> Result<(), String> {
        if self.pos >= 512 {
            return Err("Buffer overflow".to_string());
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    /// write a u8 value to the buffer
    pub fn write_u8(&mut self, val: u8) -> Result<(), String> {
        self.write(val)
    }

    /// write a u16 value to the buffer
    pub fn write_u16(&mut self, val: u16) -> Result<(), String> {
        self.write((val >> 8) as u8)?; // Write the high byte
        self.write((val & 0xFF) as u8)?; // Write the low byte
        Ok(())
    }

    /// write a u32 value to the buffer
    pub fn write_u32(&mut self, val: u32) -> Result<(), String> {
        self.write((val >> 24) as u8)?; // Write the highest byte
        self.write(((val >> 16) & 0xFF) as u8)?; // Write the second byte
        self.write(((val >> 8) & 0xFF) as u8)?; // Write the third byte
        self.write((val & 0xFF) as u8)?; // Write the lowest byte
        Ok(())
    }

    pub fn set(&mut self, pos: usize, val: u8) -> Result<(), String> {
        if pos >= 512 {
            return Err("Buffer overflow".to_string());
        }
        self.buf[pos] = val;
        Ok(())
    }
    pub fn set_u16(&mut self, pos: usize, val: u16) -> Result<(), String> {
        self.set(pos, (val >> 8) as u8)?; // Set the high byte
        self.set(pos + 1, (val & 0xFF) as u8)?; // Set the low byte
        Ok(())
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
        b.pos = 512;
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
        // Lay out: at offset 0 -> "example.com\0", then at offset 13 a
        // pointer (0xC0 0x00) pointing back to offset 0.
        let mut b = BytePacketBuffer::new();
        b.write_qname("example.com").unwrap();
        let pointer_pos = b.pos;
        b.write_u8(0xC0).unwrap();
        b.write_u8(0x00).unwrap();
        // Position the reader at the pointer.
        b.seek(pointer_pos).unwrap();
        let mut out = String::new();
        b.read_qname(&mut out).unwrap();
        assert_eq!(out, "example.com");
        // Reader must have advanced past the 2-byte pointer, not jumped.
        assert_eq!(b.pos, pointer_pos + 2);
    }
}
