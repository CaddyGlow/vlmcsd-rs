//! Client/server RPC sessions driven by complete byte frames.
//!
//! These APIs perform no I/O. Read a 16-byte header, use [`frame_len`] to bound
//! the full frame size, then deliver that exact frame to the session. The caller
//! provides transport, deadlines, timestamps, cryptographic randomness, and an
//! allocator. Sessions accept at most one outstanding operation per association.
//!
//! A complete exchange using in-memory frames (fixed salts are for this example):
//!
//! ```
//! use vlmcsd_protocol::{ActivationRequest, HostConfig, PreparedHost};
//! use vlmcsd_protocol::rpc::{ClientSession, ServerSession};
//! # fn example() -> Result<(), vlmcsd_protocol::Error> {
//! let host = PreparedHost::new(&HostConfig::default())?;
//! let mut client = ClientSession::new(false);
//! let mut server = ServerSession::new(1688);
//! let bind = client.start_bind()?;
//! let ack = server.receive(&bind, &host, [1; 16], [2; 16])?.unwrap();
//! client.finish_bind(&ack)?;
//! let request = ActivationRequest::new([0; 16], [0; 16], [0; 16], [0; 16], 0);
//! let packet = client.start_request(&request, [3; 16])?;
//! let reply = server.receive(&packet, &host, [4; 16], [5; 16])?.unwrap();
//! let response = client.receive_response(&reply)?.unwrap();
//! assert_eq!(response.client_count, 50);
//! # Ok(())
//! # }
//! # example().unwrap();
//! ```
use crate::{ActivationRequest, ActivationResponse, EncodedRequest, Error, PreparedHost};
use alloc::vec::Vec;

/// Low-level client codecs for sync and async transport adapters.
pub mod client_codec;
/// Low-level server codecs for sync and async transport adapters.
pub mod server_codec;

/// Validates a header and returns its bounded total length (16..=4096 bytes).
pub fn frame_len(header: &[u8; 16]) -> Result<usize, Error> {
    Ok(server_codec::parse_header(header)?.3)
}
fn parse(bytes: &[u8]) -> Result<server_codec::Pdu, Error> {
    let header: &[u8; 16] = bytes
        .get(..16)
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Protocol("short RPC header"))?;
    let (kind, flags, call, size) = server_codec::parse_header(header)?;
    if bytes.len() != size {
        return Err(Error::Protocol("RPC frame length mismatch"));
    }
    Ok(server_codec::Pdu {
        kind,
        flags,
        call,
        body: bytes[16..].to_vec(),
    })
}

enum ClientState {
    Fresh,
    Binding,
    Ready,
    Pending {
        encoded: EncodedRequest,
        response: client_codec::Response,
    },
    Closed,
}
/// Runtime-independent client association with response verification.
///
/// Call `start_bind`, send its frame, and pass the received frame to
/// `finish_bind`. Then alternate `start_request` and `receive_response`.
/// Deliver complete frames even when the transport supplies smaller chunks.
/// Call `close` after transport failure, cancellation, or a deadline expires.
pub struct ClientSession {
    ndr64: bool,
    call: u32,
    state: ClientState,
}
impl ClientSession {
    /// Creates an unbound association using NDR32 (`false`) or NDR64 (`true`).
    pub fn new(ndr64: bool) -> Self {
        Self {
            ndr64,
            call: 1,
            state: ClientState::Fresh,
        }
    }
    /// Builds the initial bind frame and marks the association as waiting for an ACK.
    pub fn start_bind(&mut self) -> Result<Vec<u8>, Error> {
        if !matches!(self.state, ClientState::Fresh) {
            return Err(Error::Protocol("invalid client bind sequence"));
        }
        self.state = ClientState::Binding;
        Ok(client_codec::bind_packet(self.ndr64))
    }
    /// Validates the bind acknowledgement; invalid peer data closes the association.
    pub fn finish_bind(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if !matches!(self.state, ClientState::Binding) {
            return Err(Error::Protocol("no client bind pending"));
        }
        self.state = ClientState::Closed;
        let (header, body) = self.response_frame(bytes, 12)?;
        client_codec::bind_ack(header.flags, body, self.ndr64)?;
        self.state = ClientState::Ready;
        Ok(())
    }
    /// Protects a request with a fresh random salt and builds its RPC frame.
    /// Local encoding errors leave a ready association available for retry.
    pub fn start_request(
        &mut self,
        request: &ActivationRequest,
        salt: [u8; 16],
    ) -> Result<Vec<u8>, Error> {
        if !matches!(self.state, ClientState::Ready) {
            return Err(Error::Protocol("client is unbound, busy or closed"));
        }
        let encoded = request.encode(salt)?;
        let Some(call) = self.call.checked_add(1) else {
            self.close();
            return Err(Error::Protocol("RPC call ID exhausted"));
        };
        let frame = client_codec::request_packet(self.ndr64, call, encoded.as_bytes())?;
        self.call = call;
        self.state = ClientState::Pending {
            encoded,
            response: client_codec::Response::new(self.ndr64),
        };
        Ok(frame)
    }
    /// Accepts one response frame, returning a verified response after its last fragment.
    /// Faults, malformed frames or failed integrity checks close the association.
    pub fn receive_response(&mut self, bytes: &[u8]) -> Result<Option<ActivationResponse>, Error> {
        if !matches!(self.state, ClientState::Pending { .. }) {
            return Err(Error::Protocol("no client request pending"));
        }
        let state = core::mem::replace(&mut self.state, ClientState::Closed);
        let ClientState::Pending {
            encoded,
            mut response,
        } = state
        else {
            unreachable!()
        };
        let (header, body) = self.response_frame(bytes, 2)?;
        match response.push(header.flags, body)? {
            Some(raw) => {
                let verified = encoded.verify_response(&raw)?;
                self.state = ClientState::Ready;
                Ok(Some(verified))
            }
            None => {
                self.state = ClientState::Pending { encoded, response };
                Ok(None)
            }
        }
    }
    /// Permanently invalidates the association after an interrupted exchange.
    pub fn close(&mut self) {
        self.state = ClientState::Closed;
    }
    /// Whether a new activation request may be started.
    pub fn is_ready(&self) -> bool {
        matches!(self.state, ClientState::Ready)
    }
    fn response_frame<'a>(
        &self,
        bytes: &'a [u8],
        kind: u8,
    ) -> Result<(client_codec::Header, &'a [u8]), Error> {
        let header_bytes = bytes
            .get(..16)
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::Protocol("short RPC header"))?;
        let header = client_codec::header(header_bytes, kind, self.call)?;
        if bytes.len() != header.body_len + 16 {
            return Err(Error::Protocol("RPC frame length mismatch"));
        }
        let body = &bytes[16..];
        client_codec::check_fault(&header, body)?;
        Ok((header, body))
    }
}

/// Runtime-independent server association with bounded request assembly.
///
/// Receive complete frames and send any returned response. Fresh random blocks
/// are supplied by the caller. Malformed data closes the association; instantiate
/// a new session for each new connection. Transport failure or timeout requires
/// closing the association instead of continuing a partial request.
pub struct ServerSession {
    inner: server_codec::ServerSession,
    assembly: Option<server_codec::Assembly>,
    closed: bool,
}
impl ServerSession {
    /// Creates an association advertising the supplied TCP port in bind responses.
    pub fn new(port: u16) -> Self {
        Self {
            inner: server_codec::ServerSession::new(port),
            assembly: None,
            closed: false,
        }
    }
    /// Accepts one frame, returning a response once its complete request arrives.
    /// Supply fresh cryptographically random `random` and `response_iv` blocks.
    pub fn receive(
        &mut self,
        bytes: &[u8],
        host: &PreparedHost,
        random: [u8; 16],
        response_iv: [u8; 16],
    ) -> Result<Option<Vec<u8>>, Error> {
        if self.closed {
            return Err(Error::Protocol("server association is closed"));
        }
        let result = self.receive_inner(bytes, host, random, response_iv);
        if result.is_err() {
            self.close();
        }
        result
    }
    fn receive_inner(
        &mut self,
        bytes: &[u8],
        host: &PreparedHost,
        random: [u8; 16],
        response_iv: [u8; 16],
    ) -> Result<Option<Vec<u8>>, Error> {
        let pdu = parse(bytes)?;
        let assembly = match self.assembly.take() {
            Some(mut assembly) => {
                assembly.push(pdu)?;
                assembly
            }
            None => server_codec::Assembly::new(pdu)?,
        };
        if assembly.complete() {
            return self
                .inner
                .process(assembly.finish(), host, random, response_iv)
                .map(Some);
        }
        // Only one request is in flight per association.
        self.assembly = Some(assembly);
        Ok(None)
    }
    /// Discards partial input and permanently closes this association.
    pub fn close(&mut self) {
        self.assembly = None;
        self.closed = true;
    }
    /// Whether transport and protocol processing may continue.
    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HostConfig, Version};
    use alloc::vec;

    fn host() -> PreparedHost {
        PreparedHost::new(&HostConfig::default()).unwrap()
    }
    fn pair(ndr64: bool) -> (ClientSession, ServerSession) {
        let mut client = ClientSession::new(ndr64);
        let mut server = ServerSession::new(1688);
        let bind = client.start_bind().unwrap();
        let ack = server
            .receive(&bind, &host(), [1; 16], [2; 16])
            .unwrap()
            .unwrap();
        client.finish_bind(&ack).unwrap();
        assert!(client.is_ready());
        (client, server)
    }
    fn request(version: Version) -> ActivationRequest {
        let mut request =
            ActivationRequest::new([1; 16], [2; 16], [3; 16], [4; 16], 133444736000000000);
        request.version = version;
        request
    }
    fn split(frame: &[u8], offset: usize) -> (Vec<u8>, Vec<u8>) {
        let mut first = frame[..offset].to_vec();
        first[3] = 1;
        first[8..10].copy_from_slice(&(offset as u16).to_le_bytes());
        let mut last = frame[..24].to_vec();
        last.extend_from_slice(&frame[offset..]);
        last[3] = 2;
        let length = last.len() as u16;
        last[8..10].copy_from_slice(&length.to_le_bytes());
        (first, last)
    }

    #[test]
    fn pure_sessions_roundtrip_all_versions_syntaxes_and_fragments() {
        for ndr64 in [false, true] {
            let (mut client, mut server) = pair(ndr64);
            for version in [Version::V4, Version::V5, Version::V6] {
                for fragmented in [false, true] {
                    let frame = client.start_request(&request(version), [5; 16]).unwrap();
                    assert!(!client.is_ready());
                    let response = if fragmented {
                        let (first, last) = split(&frame, 97);
                        assert!(
                            server
                                .receive(&first, &host(), [6; 16], [7; 16])
                                .unwrap()
                                .is_none()
                        );
                        server
                            .receive(&last, &host(), [6; 16], [7; 16])
                            .unwrap()
                            .unwrap()
                    } else {
                        server
                            .receive(&frame, &host(), [6; 16], [7; 16])
                            .unwrap()
                            .unwrap()
                    };
                    let result = if fragmented {
                        let (first, last) = split(&response, 65);
                        assert!(client.receive_response(&first).unwrap().is_none());
                        client.receive_response(&last).unwrap().unwrap()
                    } else {
                        client.receive_response(&response).unwrap().unwrap()
                    };
                    assert_eq!(result.version, version);
                    assert_eq!(result.client_count, 50);
                    assert_eq!(result.epid, HostConfig::default().epid);
                    assert!(client.is_ready());
                }
            }
        }
    }
    #[test]
    fn invalid_frames_and_calls_close_sessions() {
        let (mut client, mut server) = pair(false);
        let frame = client
            .start_request(&request(Version::V6), [5; 16])
            .unwrap();
        let mut response = server
            .receive(&frame, &host(), [6; 16], [7; 16])
            .unwrap()
            .unwrap();
        response[12] ^= 1;
        assert!(client.receive_response(&response).is_err());
        assert!(!client.is_ready());
        assert!(
            client
                .start_request(&request(Version::V6), [5; 16])
                .is_err()
        );
        for length in 0..frame.len() {
            let mut server = ServerSession::new(1688);
            assert!(
                server
                    .receive(&frame[..length], &host(), [6; 16], [7; 16])
                    .is_err()
            );
            assert!(server.is_closed());
        }
        let (mut client, mut server) = pair(false);
        let mut frame = client
            .start_request(&request(Version::V6), [5; 16])
            .unwrap();
        frame[20] = 99;
        let fault = server
            .receive(&frame, &host(), [6; 16], [7; 16])
            .unwrap()
            .unwrap();
        assert!(matches!(
            client.receive_response(&fault),
            Err(Error::Status(0x1c00001c))
        ));
        assert!(!server.is_closed());
    }
    #[test]
    fn invalid_bind_local_request_and_explicit_cancellation() {
        let mut fresh = ClientSession::new(false);
        assert!(fresh.start_request(&request(Version::V6), [5; 16]).is_err());
        let bind = fresh.start_bind().unwrap();
        assert!(fresh.start_bind().is_err());
        let mut server = ServerSession::new(1688);
        let mut ack = server
            .receive(&bind, &host(), [1; 16], [2; 16])
            .unwrap()
            .unwrap();
        ack[2] = 0;
        assert!(fresh.finish_bind(&ack).is_err());
        assert!(fresh.start_bind().is_err());
        let (mut client, mut server) = pair(false);
        let mut invalid = request(Version::V6);
        invalid.workstation = "x".repeat(64);
        assert!(client.start_request(&invalid, [5; 16]).is_err());
        assert!(client.is_ready());
        let frame = client
            .start_request(&request(Version::V6), [5; 16])
            .unwrap();
        let (first, _) = split(&frame, 97);
        assert!(
            server
                .receive(&first, &host(), [6; 16], [7; 16])
                .unwrap()
                .is_none()
        );
        server.close();
        client.close();
        assert!(server.is_closed());
        assert!(!client.is_ready());
        assert!(server.receive(&frame, &host(), [6; 16], [7; 16]).is_err());
    }
    #[test]
    fn frame_and_request_limits_reject_unbounded_inputs() {
        let mut header = [5, 0, 0, 3, 0x10, 0, 0, 0, 0, 16, 0, 0, 1, 0, 0, 0];
        assert_eq!(frame_len(&header).unwrap(), 4096);
        header[9] = 255;
        assert!(frame_len(&header).is_err());
        assert!(client_codec::request_packet(false, 2, &vec![0; 65536]).is_err());
    }
    #[test]
    fn corrupt_integrity_and_interleaved_requests_fail() {
        let (mut client, mut server) = pair(true);
        let frame = client
            .start_request(&request(Version::V6), [5; 16])
            .unwrap();
        let mut response = server
            .receive(&frame, &host(), [6; 16], [7; 16])
            .unwrap()
            .unwrap();
        response[80] ^= 1;
        assert!(client.receive_response(&response).is_err());
        assert!(!client.is_ready());
        let (_, mut server) = pair(true);
        let (first, mut last) = split(&frame, 97);
        assert!(
            server
                .receive(&first, &host(), [6; 16], [7; 16])
                .unwrap()
                .is_none()
        );
        last[12] ^= 1;
        assert!(server.receive(&last, &host(), [6; 16], [7; 16]).is_err());
        assert!(server.is_closed());
    }
}
