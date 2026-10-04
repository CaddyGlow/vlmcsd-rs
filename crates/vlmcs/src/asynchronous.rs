use crate::{ActivationRequest, ActivationResponse, ClientConfig, Error};
use tokio::{
    net::{TcpStream, ToSocketAddrs},
    time::timeout,
};
mod transport;

/// One bound RPC association. Requests are serialized by mutable borrowing.
pub struct Client {
    stream: TcpStream,
    config: ClientConfig,
    call: u32,
    usable: bool,
}
impl Client {
    /// Resolves, connects and binds within one deadline.
    pub async fn connect(address: impl ToSocketAddrs, config: ClientConfig) -> Result<Self, Error> {
        if config.timeout.is_zero() {
            return Err(Error::Config("timeout must be nonzero"));
        }
        let stream = timeout(config.timeout, async {
            let mut stream = TcpStream::connect(address).await?;
            transport::bind(&mut stream, config.ndr64).await?;
            Ok::<_, Error>(stream)
        })
        .await
        .map_err(|_| Error::Timeout)??;
        Ok(Self {
            stream,
            config,
            call: 1,
            usable: true,
        })
    }

    /// Sends a request and verifies the response's integrity and correlation fields.
    /// After cancellation, timeout or a peer error this client must be reconnected.
    pub async fn activate(
        &mut self,
        request: &ActivationRequest,
    ) -> Result<ActivationResponse, Error> {
        if !self.usable {
            return Err(Error::Closed);
        }
        let encoded = crate::encode(request)?;
        self.call = self.call.checked_add(1).ok_or(Error::Closed)?;
        self.usable = false;
        let bytes = timeout(
            self.config.timeout,
            transport::request(
                &mut self.stream,
                self.config.ndr64,
                self.call,
                encoded.as_bytes(),
            ),
        )
        .await
        .map_err(|_| Error::Timeout)??;
        let response = encoded.verify_response(&bytes)?;
        self.usable = true;
        Ok(response)
    }
}
