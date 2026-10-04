use crate::Error;

/// Cursor that rejects truncated fields and trailing bytes.
pub struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    /// Creates a reader over the supplied bytes.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    /// Consumes exactly the requested number of bytes.
    pub fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let (head, tail) = self
            .0
            .split_at_checked(len)
            .ok_or(Error::Protocol("truncated field"))?;
        self.0 = tail;
        Ok(head)
    }

    /// Consumes a fixed-size byte array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut value = [0; N];
        value.copy_from_slice(self.take(N)?);
        Ok(value)
    }

    /// Reads a little-endian 16-bit integer.
    pub fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    /// Reads a little-endian 32-bit integer.
    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    /// Reads a little-endian 64-bit integer.
    pub fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// Rejects unconsumed trailing bytes.
    pub fn finish(self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Protocol("trailing data"))
        }
    }
}
