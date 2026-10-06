//! Async and blocking KMS emulation over connection-oriented DCE/RPC.
//! With default features disabled, use [`ServerSession`] for `no_std` transports.
//! An allocator is required; callers supply randomness, I/O and deadlines.
//!
//! Bind a Tokio listener and pass it to `serve` with a shutdown future.
//! Protocol processing is bounded and synchronous. The `async` feature enables
//! Tokio I/O; the `blocking` feature enables standard-library sockets and threads.
//!
//! ```no_run
//! # #[cfg(feature = "async")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let listener = tokio::net::TcpListener::bind("127.0.0.1:1688").await?;
//! vlmcsd::serve(listener, vlmcsd::ServerConfig::default(), async {
//!     let _ = tokio::signal::ctrl_c().await;
//! }).await?;
//! # Ok(()) }
//! ```
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Version of this library, as declared in `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Blocking server with bounded worker threads.
#[cfg(feature = "blocking")]
pub mod blocking;
#[cfg(feature = "std")]
mod config;
#[cfg(any(feature = "async", feature = "blocking"))]
mod rpc;
#[cfg(feature = "async")]
mod server;

#[cfg(feature = "std")]
pub use config::ServerConfig;
#[cfg(feature = "async")]
pub use server::serve;
pub use vlmcsd_protocol::Error as ProtocolError;
pub use vlmcsd_protocol::rpc::ServerSession;
pub use vlmcsd_protocol::{HostConfig, PreparedHost};

/// Server configuration, socket and protocol errors.
#[cfg(feature = "std")]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Socket I/O failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Invalid host configuration or KMS packet.
    #[error(transparent)]
    Codec(#[from] vlmcsd_protocol::Error),
    /// Invalid server configuration.
    #[error("invalid configuration: {0}")]
    Config(&'static str),
    /// Invalid RPC packet.
    #[error("invalid packet: {0}")]
    Protocol(&'static str),
    /// OS randomness unavailable.
    #[error("OS randomness unavailable: {0}")]
    Random(String),
    /// Connection task failed.
    #[error(transparent)]
    #[cfg(feature = "async")]
    Task(#[from] tokio::task::JoinError),
    /// A blocking connection worker panicked.
    #[error("connection worker panicked")]
    WorkerPanic,
    /// An exchange deadline expired.
    #[error("exchange deadline expired")]
    Timeout,
}
