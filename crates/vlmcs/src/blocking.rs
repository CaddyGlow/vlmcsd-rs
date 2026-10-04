//! Blocking sockets for synchronous applications.
//! Use these operations on dedicated threads when integrating with async code.
//!
//! ```no_run
//! use vlmcs::{ActivationRequest, ClientConfig, blocking::Client};
//! # fn example() -> Result<(), vlmcs::Error> {
//! let request = ActivationRequest::new([0; 16], [0; 16], [0; 16], [0; 16], 0);
//! let mut client = Client::connect("127.0.0.1:1688", ClientConfig::default())?;
//! let response = client.activate(&request)?;
//! # Ok(())
//! # }
//! ```
use crate::{ActivationRequest, ActivationResponse, ClientConfig, Error};
use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    time::Instant,
};
mod transport;

/// One persistent association using standard-library blocking sockets.
pub struct Client {
    stream: TcpStream,
    config: ClientConfig,
    call: u32,
    usable: bool,
}
impl Client {
    /// Resolves an address, then connects and binds within one deadline.
    /// System DNS resolution is blocking and is outside the socket deadline.
    /// Supply a socket address to avoid DNS resolution.
    pub fn connect(address: impl ToSocketAddrs, config: ClientConfig) -> Result<Self, Error> {
        if config.timeout.is_zero() {
            return Err(Error::Config("timeout must be nonzero"));
        }
        let addresses: Vec<_> = address.to_socket_addrs()?.collect();
        let deadline = Instant::now()
            .checked_add(config.timeout)
            .ok_or(Error::Config("timeout exceeds clock range"))?;
        let mut last = None;
        let mut stream = None;
        for address in addresses {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(Error::Timeout)?;
            match TcpStream::connect_timeout(&address, remaining) {
                Ok(socket) => {
                    stream = Some(socket);
                    break;
                }
                Err(error) => last = Some(error),
            }
        }
        let mut stream = stream.ok_or_else(|| {
            last.map(io_error)
                .unwrap_or(Error::Config("address resolved to no endpoints"))
        })?;
        transport::bind(&mut stream, config.ndr64, deadline)?;
        Ok(Self {
            stream,
            config,
            call: 1,
            usable: true,
        })
    }
    /// Sends and verifies a response within one deadline, including all fragments.
    /// After a failed network exchange, reconnect before reusing this client.
    pub fn activate(&mut self, request: &ActivationRequest) -> Result<ActivationResponse, Error> {
        if !self.usable {
            return Err(Error::Closed);
        }
        let encoded = crate::encode(request)?;
        let deadline = Instant::now()
            .checked_add(self.config.timeout)
            .ok_or(Error::Config("timeout exceeds clock range"))?;
        self.call = self.call.checked_add(1).ok_or(Error::Closed)?;
        self.usable = false;
        let bytes = transport::request(
            &mut self.stream,
            self.config.ndr64,
            self.call,
            encoded.as_bytes(),
            deadline,
        )?;
        let response = encoded.verify_response(&bytes)?;
        self.usable = true;
        Ok(response)
    }
}

pub(crate) struct Deadline<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
}
impl<'a> Deadline<'a> {
    pub(crate) fn new(stream: &'a mut TcpStream, deadline: Instant) -> Self {
        Self { stream, deadline }
    }
    fn remaining(&self) -> std::io::Result<std::time::Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "exchange deadline expired")
            })
    }
}
impl Read for Deadline<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}
impl Write for Deadline<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}
pub(crate) fn io_error(error: std::io::Error) -> Error {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => Error::Timeout,
        _ => Error::Io(error),
    }
}
