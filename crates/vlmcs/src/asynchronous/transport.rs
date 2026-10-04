use crate::{Error, rpc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

async fn receive(stream: &mut TcpStream, kind: u8, call: u32) -> Result<(u8, Vec<u8>), Error> {
    let mut bytes = [0; 16];
    stream.read_exact(&mut bytes).await?;
    let header = rpc::header(&bytes, kind, call)?;
    let mut body = vec![0; header.body_len];
    stream.read_exact(&mut body).await?;
    rpc::check_fault(&header, &body)?;
    Ok((header.flags, body))
}
pub(super) async fn bind(stream: &mut TcpStream, ndr64: bool) -> Result<(), Error> {
    stream.write_all(&rpc::bind_packet(ndr64)).await?;
    let (flags, body) = receive(stream, 12, 1).await?;
    rpc::bind_ack(flags, &body, ndr64)
}
pub(super) async fn request(
    stream: &mut TcpStream,
    ndr64: bool,
    call: u32,
    raw: &[u8],
) -> Result<Vec<u8>, Error> {
    stream
        .write_all(&rpc::request_packet(ndr64, call, raw)?)
        .await?;
    let mut response = rpc::Response::new(ndr64);
    loop {
        let (flags, body) = receive(stream, 2, call).await?;
        if let Some(bytes) = response.push(flags, &body)? {
            return Ok(bytes);
        }
    }
}
