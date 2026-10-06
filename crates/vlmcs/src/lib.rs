//! KMS clients with shared codecs, native async I/O and blocking I/O.
//! With default features disabled, use [`ClientSession`] for `no_std` transports.
//! An allocator is required; callers supply time, randomness, I/O and deadlines.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
/// Version of this library, as declared in `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(feature = "async")]
mod asynchronous;
#[cfg(any(feature = "async", feature = "blocking"))]
mod rpc;
#[cfg(feature = "async")]
pub use asynchronous::Client;
/// Blocking client using standard-library sockets.
#[cfg(feature = "blocking")]
pub mod blocking;

#[cfg(feature = "std")]
use std::time::Duration;
pub use vlmcsd_protocol::Error as ProtocolError;
pub use vlmcsd_protocol::rpc::ClientSession;
pub use vlmcsd_protocol::{ActivationRequest, ActivationResponse, Version};

/// Client transport and protocol errors.
#[cfg(feature = "std")]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Socket operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// KMS data or configuration failed validation.
    #[error(transparent)]
    Codec(#[from] vlmcsd_protocol::Error),
    /// RPC data failed validation.
    #[error("invalid RPC packet: {0}")]
    Protocol(&'static str),
    /// Server returned an RPC fault or KMS error status.
    #[error("server returned status 0x{0:08x}")]
    Status(u32),
    /// Connect, bind or request deadline expired.
    #[error("exchange deadline expired")]
    Timeout,
    /// The association is unusable after an interrupted or failed exchange.
    #[error("connection is unusable; reconnect before sending another request")]
    Closed,
    /// Invalid client configuration.
    #[error("invalid configuration: {0}")]
    Config(&'static str),
    /// OS random source failed.
    #[error("OS randomness unavailable: {0}")]
    Random(String),
}

/// Transport configuration for a single persistent association.
#[cfg(feature = "std")]
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Deadline per complete connect/bind or activation exchange.
    /// Blocking system DNS resolution is outside this deadline.
    pub timeout: Duration,
    /// Request NDR64 instead of NDR32; rejection is an error.
    pub ndr64: bool,
}
#[cfg(feature = "std")]
impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            ndr64: false,
        }
    }
}

#[cfg(any(feature = "async", feature = "blocking"))]
fn encode(request: &ActivationRequest) -> Result<vlmcsd_protocol::EncodedRequest, Error> {
    let mut salt = [0; 16];
    getrandom::fill(&mut salt).map_err(|e| Error::Random(e.to_string()))?;
    Ok(request.encode(salt)?)
}
