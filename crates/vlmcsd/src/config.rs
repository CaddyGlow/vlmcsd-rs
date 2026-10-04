use std::{num::NonZeroUsize, time::Duration};
use vlmcsd_protocol::HostConfig;

/// Limits applied to each server instance.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Maximum simultaneously running connection tasks.
    pub max_connections: NonZeroUsize,
    /// Deadline for a complete RPC exchange, including all fragments and the write.
    pub exchange_timeout: Duration,
    /// Maximum requests per connection before reconnecting is required.
    pub max_exchanges: NonZeroUsize,
    /// Time allowed for active connections to finish after shutdown is requested.
    pub shutdown_grace: Duration,
    /// Host identity and emulated activation response policy.
    pub host: HostConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_connections: NonZeroUsize::new(256).unwrap_or(NonZeroUsize::MIN),
            exchange_timeout: Duration::from_secs(30),
            max_exchanges: NonZeroUsize::new(1024).unwrap_or(NonZeroUsize::MIN),
            shutdown_grace: Duration::from_secs(5),
            host: HostConfig::default(),
        }
    }
}
