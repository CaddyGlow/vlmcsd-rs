use super::{Deadline, io_error};
use crate::{Error, rpc};
use std::{
    io::{Read, Write},
    net::TcpStream,
    time::Instant,
};

fn receive(stream: &mut Deadline<'_>, kind: u8, call: u32) -> Result<(u8, Vec<u8>), Error> {
    let mut bytes = [0; 16];
    stream.read_exact(&mut bytes).map_err(io_error)?;
    let header = rpc::header(&bytes, kind, call)?;
    let mut body = vec![0; header.body_len];
    stream.read_exact(&mut body).map_err(io_error)?;
    rpc::check_fault(&header, &body)?;
    Ok((header.flags, body))
}
pub(super) fn bind(socket: &mut TcpStream, ndr64: bool, deadline: Instant) -> Result<(), Error> {
    let mut stream = Deadline::new(socket, deadline);
    stream
        .write_all(&rpc::bind_packet(ndr64))
        .map_err(io_error)?;
    let (flags, body) = receive(&mut stream, 12, 1)?;
    rpc::bind_ack(flags, &body, ndr64)
}
pub(super) fn request(
    socket: &mut TcpStream,
    ndr64: bool,
    call: u32,
    raw: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, Error> {
    let mut stream = Deadline::new(socket, deadline);
    stream
        .write_all(&rpc::request_packet(ndr64, call, raw)?)
        .map_err(io_error)?;
    let mut response = rpc::Response::new(ndr64);
    loop {
        let (flags, body) = receive(&mut stream, 2, call)?;
        if let Some(bytes) = response.push(flags, &body)? {
            return Ok(bytes);
        }
    }
}
