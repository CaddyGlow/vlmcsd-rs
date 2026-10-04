//! KMS V4/V5/V6 codecs and crypto for `no_std` environments with an allocator.
//! Callers supply timestamps and cryptographically random salts.
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
extern crate alloc;
#[cfg(test)]
extern crate std;
mod aes;
mod client;
pub use client::{ActivationRequest, ActivationResponse, EncodedRequest, Version};
mod protocol;
/// Runtime-independent RPC framing and client/server associations.
pub mod rpc;
/// Checked little-endian wire reader shared by transports.
pub mod wire;
pub use protocol::{HostConfig, PreparedHost, respond_into};

/// Errors returned by configuration or protocol processing.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A configuration value is outside its supported range.
    #[error("invalid configuration: {0}")]
    Config(&'static str),
    /// A peer sent invalid or unsupported protocol data.
    #[error("invalid packet: {0}")]
    Protocol(&'static str),
    /// RPC fault or KMS error status returned by a peer.
    #[error("server returned status 0x{0:08x}")]
    Status(u32),
}
