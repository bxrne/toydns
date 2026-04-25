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
    fn seek(&mut self, pos: usize) -> Result<(), String> {
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
