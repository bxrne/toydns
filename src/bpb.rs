pub struct BytePacketBuffer {
    pub buf: [u8; 512], // DNS messages are typically limited to 512 bytes
    pos: usize,         // Current position in the buffer
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
    fn read(&mut self) -> Result<u8, String> {
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
        let mut pos = self.position();

        // Loop until we encounter a zero byte, which indicates the end of the domain name
        loop {
            let len = self.get(pos)?; // Get the length of the next label
            if len == 0 {
                break; // End of domain name
            }

            // Check for pointer (compression)
            if (len & 0xC0) == 0xC0 {
                let b2 = self.get(pos + 1)?; // Get the second byte of the pointer
                let offset = (((len as u16) ^ 0xC0) << 8) | (b2 as u16); // Calculate the offset for the pointer
                self.seek(offset as usize)?; // Move to the offset position
                return self.read_qname(outstr); // Recursively read the domain name from the pointer location
            } else {
                pos += 1; // Move past the length byte
                let label_bytes = self.get_range(pos, len as usize)?; // Get the label bytes
                let label = std::str::from_utf8(label_bytes)
                    .map_err(|_| "Invalid UTF-8 in label".to_string())?; // Convert bytes to string
                outstr.push_str(label); // Append the label to the output string
                outstr.push('.'); // Add a dot after each label
                pos += len as usize; // Move to the next label
            }
        }

        if !outstr.is_empty() {
            outstr.pop(); // Remove the trailing dot if there is one
        }

        self.seek(pos + 1)?; // Move past the null byte at the end of the domain name
        Ok(())
    }
}
