use alloc::{collections::BTreeMap, format, string::String, vec::Vec};

use crate::Error;
use crate::{PreparedHost, protocol, wire::Reader};

const HEADER_SIZE: usize = 16;
const MAX_PDU: usize = 4096;
const MAX_CONTEXTS: usize = 32;
const INTERFACE: [u8; 16] = [
    0x75, 0x21, 0xc8, 0x51, 0x4e, 0x84, 0x50, 0x47, 0xb0, 0xd8, 0xec, 0x25, 0x55, 0x55, 0xbc, 0x06,
];
const NDR32: [u8; 16] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
];
const NDR64: [u8; 16] = [
    0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Syntax {
    Ndr32,
    Ndr64,
}

/// Server-side RPC association and negotiated presentation contexts.
pub struct ServerSession {
    contexts: BTreeMap<u16, Syntax>,
    bound: bool,
    port: u16,
    transmit_limit: usize,
}

/// Parsed complete RPC fragment with bounded body length.
pub struct Pdu {
    /// RPC packet type.
    pub kind: u8,
    /// RPC fragment flags.
    pub flags: u8,
    /// Call identifier.
    pub call: u32,
    /// Fragment body.
    pub body: Vec<u8>,
}

impl ServerSession {
    /// Creates an unbound server association for the given listening port.
    pub fn new(port: u16) -> Self {
        Self {
            contexts: BTreeMap::new(),
            bound: false,
            port,
            transmit_limit: MAX_PDU,
        }
    }

    /// Processes an assembled call with caller-provided fresh random blocks.
    pub fn process(
        &mut self,
        pdu: Pdu,
        host: &PreparedHost,
        random: [u8; 16],
        response_iv: [u8; 16],
    ) -> Result<Vec<u8>, Error> {
        if pdu.body.len() > MAX_PDU || pdu.flags & 2 == 0 || pdu.flags & !0x13 != 0 {
            return Err(Error::Protocol("invalid assembled request"));
        }
        let mut output = Vec::with_capacity(512);
        output.resize(HEADER_SIZE, 0);
        let kind = match pdu.kind {
            11 | 14 => {
                if (pdu.kind == 11 && self.bound) || (pdu.kind == 14 && !self.bound) {
                    return Err(Error::Protocol("invalid bind sequence"));
                }
                output.extend_from_slice(&self.bind(&pdu.body, pdu.kind == 14)?);
                if pdu.kind == 11 { 12 } else { 15 }
            }
            0 if self.bound => self.request(&pdu.body, host, &mut output, random, response_iv)?,
            _ => return Err(Error::Protocol("unexpected RPC packet type")),
        };
        if output.len() > self.transmit_limit {
            return Err(Error::Protocol("response exceeds negotiated fragment size"));
        }
        let flags = if matches!(kind, 12 | 15) {
            3 | (pdu.flags & 0x10)
        } else {
            3
        };
        let length = output.len() as u16;
        output[..8].copy_from_slice(&[5, 0, kind, flags, 0x10, 0, 0, 0]);
        output[8..10].copy_from_slice(&length.to_le_bytes());
        output[12..16].copy_from_slice(&pdu.call.to_le_bytes());
        Ok(output)
    }

    fn bind(&mut self, bytes: &[u8], alter: bool) -> Result<Vec<u8>, Error> {
        let mut input = Reader::new(bytes);
        let peer_transmit = input.u16()?;
        let peer_receive = input.u16()?;
        input.u32()?; // Association group: this TCP connection owns its contexts.
        let count = usize::from(input.array::<1>()?[0]);
        if input.take(3)? != [0; 3]
            || !(1..=MAX_CONTEXTS).contains(&count)
            || peer_transmit < 1024
            || peer_receive < 1024
        {
            return Err(Error::Protocol("invalid bind limits"));
        }
        let mut contexts = self.contexts.clone();
        let mut seen = Vec::with_capacity(count);
        let mut results = Vec::with_capacity(count * 24);
        for _ in 0..count {
            let id = input.u16()?;
            let transfers = usize::from(input.array::<1>()?[0]);
            if input.array::<1>()?[0] != 0
                || transfers == 0
                || transfers > MAX_CONTEXTS
                || seen.contains(&id)
            {
                return Err(Error::Protocol("invalid presentation context"));
            }
            seen.push(id);
            let interface = input.array::<16>()?;
            let interface_version = input.u32()?;
            let supported = interface == INTERFACE && interface_version == 1;
            let mut selected = None;
            for _ in 0..transfers {
                let uuid = input.array::<16>()?;
                let version = input.u32()?;
                if supported && selected.is_none() {
                    selected = match (uuid, version) {
                        (NDR32, 2) => Some(Syntax::Ndr32),
                        (NDR64, 1) => Some(Syntax::Ndr64),
                        _ => None,
                    };
                }
            }
            if let Some(syntax) = selected {
                if contexts.get(&id).is_some_and(|old| *old != syntax) {
                    return Err(Error::Protocol("context ID cannot change transfer syntax"));
                }
                contexts.insert(id, syntax);
                results.extend_from_slice(&[0; 4]);
                results.extend_from_slice(&if syntax == Syntax::Ndr32 {
                    NDR32
                } else {
                    NDR64
                });
                results.extend_from_slice(
                    &(if syntax == Syntax::Ndr32 { 2u32 } else { 1 }).to_le_bytes(),
                );
            } else {
                results.extend_from_slice(&2u16.to_le_bytes());
                results.extend_from_slice(&(if supported { 2u16 } else { 1 }).to_le_bytes());
                results.extend_from_slice(&[0; 20]);
            }
        }
        input.finish()?;
        if contexts.len() > MAX_CONTEXTS {
            return Err(Error::Protocol("too many negotiated contexts"));
        }
        self.contexts = contexts;
        self.bound = true;
        self.transmit_limit = usize::from(peer_receive).min(MAX_PDU);
        let mut out = Vec::with_capacity(20 + results.len());
        out.extend_from_slice(&(self.transmit_limit as u16).to_le_bytes());
        out.extend_from_slice(&(usize::from(peer_transmit).min(MAX_PDU) as u16).to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        let address = if alter {
            String::new()
        } else {
            format!("{}\0", self.port)
        };
        out.extend_from_slice(&(address.len() as u16).to_le_bytes());
        out.extend_from_slice(address.as_bytes());
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out.extend_from_slice(&(count as u32).to_le_bytes());
        out.extend_from_slice(&results);
        Ok(out)
    }

    fn request(
        &self,
        bytes: &[u8],
        host: &PreparedHost,
        out: &mut Vec<u8>,
        random: [u8; 16],
        response_iv: [u8; 16],
    ) -> Result<u8, Error> {
        let mut input = Reader::new(bytes);
        input.u32()?; // Allocation hint is advisory, never used to allocate.
        let context = input.u16()?;
        let opnum = input.u16()?;
        let Some(syntax) = self.contexts.get(&context) else {
            return Ok(fault(out, context, 0x1c00001c));
        };
        if opnum != 0 {
            return Ok(fault(out, context, 0x1c010002));
        }
        let (len, size) = if *syntax == Syntax::Ndr32 {
            (u64::from(input.u32()?), u64::from(input.u32()?))
        } else {
            (input.u64()?, input.u64()?)
        };
        if len != size || !matches!(len, 252 | 260) {
            return Err(Error::Protocol("invalid NDR request lengths"));
        }
        let request = input.take(len as usize)?;
        input.finish()?;
        let start = out.len();
        let width = if *syntax == Syntax::Ndr32 { 4 } else { 8 };
        let response_start = start + 8 + 3 * width;
        out.resize(response_start, 0);
        protocol::respond_into(request, host, out, random, response_iv)?;
        let response_len = (out.len() - response_start) as u64;
        for (index, value) in [response_len, 0x20000, response_len]
            .into_iter()
            .enumerate()
        {
            let offset = start + 8 + index * width;
            out[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
        }
        let padded_len = start + (out.len() - start).next_multiple_of(4);
        out.resize(padded_len + 4, 0); // NDR alignment followed by success status.
        let stub_len = (out.len() - start - 8) as u32;
        out[start..start + 4].copy_from_slice(&stub_len.to_le_bytes());
        out[start + 4..start + 6].copy_from_slice(&context.to_le_bytes());
        Ok(2)
    }
}

fn fault(out: &mut Vec<u8>, context: u16, status: u32) -> u8 {
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&context.to_le_bytes());
    out.extend_from_slice(&[0; 2]);
    out.extend_from_slice(&status.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    3
}

/// Validates a server-side RPC header and returns kind, flags, call ID and total size.
pub fn parse_header(header: &[u8; 16]) -> Result<(u8, u8, u32, usize), Error> {
    let mut input = Reader::new(header);
    if input.take(2)? != [5, 0] {
        return Err(Error::Protocol("unsupported RPC version"));
    }
    let kind = input.array::<1>()?[0];
    let flags = input.array::<1>()?[0];
    if flags & !0x13 != 0 || input.array::<4>()? != [0x10, 0, 0, 0] {
        return Err(Error::Protocol("unsupported RPC flags or byte order"));
    }
    let size = usize::from(input.u16()?);
    if !(HEADER_SIZE..=MAX_PDU).contains(&size) || input.u16()? != 0 {
        return Err(Error::Protocol(
            "invalid RPC length or authentication trailer",
        ));
    }
    let call = input.u32()?;
    Ok((kind, flags, call, size))
}

/// Bounded request-fragment assembler.
pub struct Assembly {
    pdu: Pdu,
    fragments: usize,
}
impl Assembly {
    /// Accepts the first fragment of one request.
    pub fn new(pdu: Pdu) -> Result<Self, Error> {
        if pdu.body.len() > MAX_PDU || pdu.flags & !0x13 != 0 || pdu.flags & 1 == 0 {
            return Err(Error::Protocol("missing first fragment"));
        }
        if pdu.flags & 2 == 0 && (pdu.kind != 0 || pdu.body.len() < 8) {
            return Err(Error::Protocol("invalid first fragment"));
        }
        Ok(Self { pdu, fragments: 1 })
    }
    /// Whether the last fragment has arrived.
    pub fn complete(&self) -> bool {
        self.pdu.flags & 2 != 0
    }
    /// Appends a matching fragment within the byte and fragment limits.
    pub fn push(&mut self, next: Pdu) -> Result<(), Error> {
        if self.complete()
            || next.kind != 0
            || next.call != self.pdu.call
            || next.flags & 1 != 0
            || next.body.len() <= 8
            || next.body[4..8] != self.pdu.body[4..8]
            || self.pdu.body.len() + next.body.len() - 8 > MAX_PDU
            || self.fragments >= 16
        {
            return Err(Error::Protocol("invalid request fragmentation"));
        }
        self.pdu.body.extend_from_slice(&next.body[8..]);
        self.pdu.flags = next.flags;
        self.fragments += 1;
        Ok(())
    }
    /// Returns the assembled call; only call after `complete` is true.
    pub fn finish(self) -> Pdu {
        self.pdu
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn proposal(id: u16, syntax: [u8; 16], version: u32) -> Vec<u8> {
        let mut out = vec![0, 16, 0, 16, 0, 0, 0, 0, 1, 0, 0, 0];
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&[1, 0]);
        out.extend_from_slice(&INTERFACE);
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&syntax);
        out.extend_from_slice(&version.to_le_bytes());
        out
    }

    #[test]
    fn truncated_bind_fields_are_rejected_without_mutating_contexts() {
        let valid = proposal(7, NDR32, 2);
        for size in 0..valid.len() {
            let mut session = ServerSession::new(1688);
            assert!(
                session.bind(&valid[..size], false).is_err(),
                "length {size}"
            );
            assert!(!session.bound);
            assert!(session.contexts.is_empty());
        }
    }

    #[test]
    fn bind_selects_supported_syntax_from_multiple_offers() {
        let mut body = proposal(7, [0; 16], 99);
        body[14] = 2;
        body.extend_from_slice(&NDR64);
        body.extend_from_slice(&1u32.to_le_bytes());
        let mut session = ServerSession::new(21688);
        let response = session.bind(&body, false).unwrap();
        assert_eq!(session.contexts.get(&7), Some(&Syntax::Ndr64));
        assert!(response.windows(6).any(|window| window == b"21688\0"));
    }

    #[test]
    fn unsupported_interface_and_syntax_versions_are_rejected() {
        let mut wrong_interface = proposal(7, NDR32, 2);
        wrong_interface[16] ^= 1;
        let mut wrong_interface_version = proposal(7, NDR32, 2);
        wrong_interface_version[32] = 2;
        for body in [
            wrong_interface,
            wrong_interface_version,
            proposal(7, NDR32, 1),
            proposal(7, NDR64, 2),
        ] {
            let mut session = ServerSession::new(1688);
            let response = session.bind(&body, false).unwrap();
            assert_eq!(&response[20..22], &2u16.to_le_bytes());
            assert!(session.contexts.is_empty());
        }
    }

    #[test]
    fn alter_context_preserves_existing_ids_and_enforces_total_limit() {
        let mut session = ServerSession::new(1688);
        session.bind(&proposal(0, NDR32, 2), false).unwrap();
        for id in 1..32 {
            session.bind(&proposal(id, NDR64, 1), true).unwrap();
        }
        assert!(session.bind(&proposal(32, NDR32, 2), true).is_err());
        assert_eq!(session.contexts.len(), 32);
        assert!(session.bind(&proposal(0, NDR64, 1), true).is_err());
        assert_eq!(session.contexts.get(&0), Some(&Syntax::Ndr32));
    }

    #[test]
    fn duplicate_contexts_and_excess_counts_are_rejected() {
        let mut duplicate = proposal(7, NDR32, 2);
        let item = duplicate[12..].to_vec();
        duplicate[8] = 2;
        duplicate.extend_from_slice(&item);
        assert!(ServerSession::new(1688).bind(&duplicate, false).is_err());
        for offset in [8, 14] {
            let mut body = proposal(7, NDR32, 2);
            body[offset] = 255;
            assert!(ServerSession::new(1688).bind(&body, false).is_err());
        }
    }
}
