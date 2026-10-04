use crate::Error;
pub(crate) use codec::{Header, bind_packet};
use vlmcsd_protocol::rpc::client_codec as codec;
pub(crate) fn header(bytes: &[u8; 16], kind: u8, call: u32) -> Result<Header, Error> {
    codec::header(bytes, kind, call).map_err(convert)
}
pub(crate) fn check_fault(header: &Header, body: &[u8]) -> Result<(), Error> {
    codec::check_fault(header, body).map_err(convert)
}
pub(crate) fn bind_ack(flags: u8, body: &[u8], ndr64: bool) -> Result<(), Error> {
    codec::bind_ack(flags, body, ndr64).map_err(convert)
}
pub(crate) struct Response(codec::Response);
impl Response {
    pub(crate) fn new(ndr64: bool) -> Self {
        Self(codec::Response::new(ndr64))
    }
    pub(crate) fn push(&mut self, flags: u8, body: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.0.push(flags, body).map_err(convert)
    }
}
fn convert(error: vlmcsd_protocol::Error) -> Error {
    match error {
        vlmcsd_protocol::Error::Protocol(message) => Error::Protocol(message),
        vlmcsd_protocol::Error::Status(status) => Error::Status(status),
        other => Error::Codec(other),
    }
}

pub(crate) fn request_packet(ndr64: bool, call: u32, raw: &[u8]) -> Result<Vec<u8>, Error> {
    codec::request_packet(ndr64, call, raw).map_err(convert)
}
