use crate::Error;
use crate::wire::Reader;
use alloc::{vec, vec::Vec};

const INTERFACE: [u8; 16] = [
    0x75, 0x21, 0xc8, 0x51, 0x4e, 0x84, 0x50, 0x47, 0xb0, 0xd8, 0xec, 0x25, 0x55, 0x55, 0xbc, 0x06,
];
const NDR32: [u8; 16] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
];
const NDR64: [u8; 16] = [
    0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36,
];

/// Encodes a bounded RPC header and body.
fn packet(kind: u8, call: u32, body: &[u8]) -> Vec<u8> {
    let mut packet = vec![5, 0, kind, 3, 0x10, 0, 0, 0];
    packet.extend_from_slice(&((body.len() + 16) as u16).to_le_bytes());
    packet.extend_from_slice(&[0; 2]);
    packet.extend_from_slice(&call.to_le_bytes());
    packet.extend_from_slice(body);
    packet
}

/// Validated response header.
pub struct Header {
    /// RPC packet type.
    pub kind: u8,
    /// Fragment flags.
    pub flags: u8,
    /// Bounded body length to read from the transport.
    pub body_len: usize,
}
/// Validates a response header against the expected type and call ID.
pub fn header(bytes: &[u8; 16], expected_kind: u8, call: u32) -> Result<Header, Error> {
    let mut input = Reader::new(bytes);
    if input.take(2)? != [5, 0] {
        return Err(Error::Protocol("unsupported RPC version"));
    }
    let kind = input.array::<1>()?[0];
    let flags = input.array::<1>()?[0];
    if flags & !0x13 != 0 || input.take(4)? != [0x10, 0, 0, 0] {
        return Err(Error::Protocol("invalid flags or byte order"));
    }
    let size = usize::from(input.u16()?);
    if !(16..=4096).contains(&size) || input.u16()? != 0 || input.u32()? != call {
        return Err(Error::Protocol("invalid length, authentication or call ID"));
    }
    if kind != expected_kind && kind != 3 {
        return Err(Error::Protocol("unexpected packet type"));
    }
    Ok(Header {
        kind,
        flags,
        body_len: size - 16,
    })
}
/// Returns a server status error for an RPC fault.
pub fn check_fault(header: &Header, body: &[u8]) -> Result<(), Error> {
    if header.kind == 3 {
        let mut fault = Reader::new(body);
        fault.take(8)?;
        return Err(Error::Status(fault.u32()?));
    }
    Ok(())
}

/// Builds the initial bind for NDR32 or NDR64.
pub fn bind_packet(ndr64: bool) -> Vec<u8> {
    let mut body = vec![0, 16, 0, 16, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0];
    body.extend_from_slice(&INTERFACE);
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(&if ndr64 { NDR64 } else { NDR32 });
    body.extend_from_slice(&(if ndr64 { 1u32 } else { 2 }).to_le_bytes());
    packet(11, 1, &body)
}

/// Validates an acknowledgement for the selected syntax.
pub fn bind_ack(flags: u8, body: &[u8], ndr64: bool) -> Result<(), Error> {
    if flags & 3 != 3 {
        return Err(Error::Protocol("fragmented bind acknowledgement"));
    }
    let mut input = Reader::new(body);
    if input.u16()? < 1024 || input.u16()? < 1024 {
        return Err(Error::Protocol("unsupported fragment limit"));
    }
    input.u32()?;
    let size = usize::from(input.u16()?);
    input.take(size)?;
    input.take((4 - (10 + size) % 4) % 4)?;
    if input.u32()? != 1 || input.u16()? != 0 || input.u16()? != 0 {
        return Err(Error::Protocol("presentation context rejected"));
    }
    if input.array::<16>()? != if ndr64 { NDR64 } else { NDR32 }
        || input.u32()? != if ndr64 { 1 } else { 2 }
    {
        return Err(Error::Protocol("unexpected transfer syntax"));
    }
    input.finish()?;
    Ok(())
}

/// Builds an activation call from protected KMS request bytes.
pub fn request_packet(ndr64: bool, call: u32, raw: &[u8]) -> Result<Vec<u8>, Error> {
    if !matches!(raw.len(), 252 | 260) {
        return Err(Error::Protocol("invalid KMS request length"));
    }
    let width = if ndr64 { 8 } else { 4 };
    let mut body = ((raw.len() + 2 * width) as u32).to_le_bytes().to_vec();
    body.extend_from_slice(&[0; 4]);
    for _ in 0..2 {
        body.extend_from_slice(&(raw.len() as u64).to_le_bytes()[..width]);
    }
    body.extend_from_slice(raw);
    Ok(packet(0, call, &body))
}

/// Bounded response-fragment assembler.
pub struct Response {
    stub: Vec<u8>,
    fragments: usize,
    ndr64: bool,
}
impl Response {
    /// Creates a response assembler for the selected syntax.
    pub fn new(ndr64: bool) -> Self {
        Self {
            stub: Vec::new(),
            fragments: 0,
            ndr64,
        }
    }
    /// Accepts one fragment, returning KMS bytes when complete.
    pub fn push(&mut self, flags: u8, body: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if self.fragments >= 16 || (flags & 1 != 0) != (self.fragments == 0) {
            return Err(Error::Protocol("invalid fragment sequence"));
        }
        self.fragments += 1;
        let mut input = Reader::new(body);
        input.u32()?;
        if input.u16()? != 0 || input.take(2)? != [0, 0] {
            return Err(Error::Protocol("invalid response context"));
        }
        if body.len() <= 8 || self.stub.len() + body.len() - 8 > 4096 {
            return Err(Error::Protocol("response exceeds assembly limit"));
        }
        self.stub.extend_from_slice(&body[8..]);
        if flags & 2 != 0 {
            return decode_stub(&self.stub, self.ndr64).map(Some);
        }
        if self.fragments == 16 {
            return Err(Error::Protocol("too many response fragments"));
        }
        Ok(None)
    }
}

fn decode_stub(stub: &[u8], ndr64: bool) -> Result<Vec<u8>, Error> {
    let mut input = Reader::new(stub);
    let length = if ndr64 {
        input.u64()?
    } else {
        u64::from(input.u32()?)
    };
    let pointer = if ndr64 {
        input.u64()?
    } else {
        u64::from(input.u32()?)
    };
    if pointer == 0 {
        let status = input.u32()?;
        return Err(if status == 0 {
            Error::Protocol("null response pointer")
        } else {
            Error::Status(status)
        });
    }
    let size = if ndr64 {
        input.u64()?
    } else {
        u64::from(input.u32()?)
    };
    if length != size || length > 512 {
        return Err(Error::Protocol("invalid NDR response lengths"));
    }
    let bytes = input.take(length as usize)?.to_vec();
    input.take((4 - length as usize % 4) % 4)?;
    let status = input.u32()?;
    if status != 0 {
        return Err(Error::Status(status));
    }
    input.finish()?;
    Ok(bytes)
}
