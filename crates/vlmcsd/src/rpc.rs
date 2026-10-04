use crate::Error;
#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use vlmcsd_protocol::PreparedHost;
pub(crate) use vlmcsd_protocol::rpc::server_codec::{Assembly, Pdu, parse_header};

pub(crate) struct Session {
    inner: vlmcsd_protocol::rpc::server_codec::ServerSession,
}
impl Session {
    pub(crate) fn new(port: u16) -> Self {
        Self {
            inner: vlmcsd_protocol::rpc::server_codec::ServerSession::new(port),
        }
    }
    /// Returns false on clean EOF between PDUs. The caller times out the entire exchange.
    #[cfg(feature = "async")]
    pub async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        stream: &mut S,
        host: &PreparedHost,
    ) -> Result<bool, Error> {
        let Some(pdu) = read_pdu(stream).await? else {
            return Ok(false);
        };
        let mut assembly = Assembly::new(pdu)?;
        while !assembly.complete() {
            let next = read_pdu(stream)
                .await?
                .ok_or(Error::Protocol("incomplete fragmented request"))?;
            assembly.push(next)?;
        }
        let output =
            self.inner
                .process(assembly.finish(), host, random_block()?, random_block()?)?;
        stream.write_all(&output).await?;
        Ok(true)
    }

    #[cfg(feature = "blocking")]
    pub(crate) fn process(&mut self, pdu: Pdu, host: &PreparedHost) -> Result<Vec<u8>, Error> {
        Ok(self
            .inner
            .process(pdu, host, random_block()?, random_block()?)?)
    }
}
fn random_block() -> Result<[u8; 16], Error> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|e| Error::Random(e.to_string()))?;
    Ok(bytes)
}
#[cfg(feature = "async")]
async fn read_pdu<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Option<Pdu>, Error> {
    let mut header = [0; 16];
    if stream.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut header[1..]).await?;
    let (kind, flags, call, size) = parse_header(&header)?;
    let mut body = vec![0; size - 16];
    stream.read_exact(&mut body).await?;
    Ok(Some(Pdu {
        kind,
        flags,
        call,
        body,
    }))
}

#[cfg(all(test, feature = "async"))]
mod tests {
    use super::*;
    use crate::HostConfig;
    #[cfg(feature = "async")]
    #[tokio::test]
    async fn stalled_response_write_is_cancelable() {
        let (mut client, mut server) = tokio::io::duplex(80);
        let body = vlmcsd_protocol::rpc::client_codec::bind_packet(false)[16..].to_vec();
        let mut packet = vec![5, 0, 11, 3, 0x10, 0, 0, 0];
        packet.extend_from_slice(&((body.len() + 16) as u16).to_le_bytes());
        packet.extend_from_slice(&[0; 6]);
        packet.extend_from_slice(&body);
        client.write_all(&packet).await.unwrap();
        // First response fits. A second bind/alter response will fill the unread buffer.
        let mut session = Session::new(1688);
        session
            .exchange(
                &mut server,
                &PreparedHost::new(&HostConfig::default()).unwrap(),
            )
            .await
            .unwrap();
        packet[2] = 14;
        client.write_all(&packet).await.unwrap();
        let host = PreparedHost::new(&HostConfig::default()).unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                session.exchange(&mut server, &host)
            )
            .await
            .is_err()
        );
    }
}
