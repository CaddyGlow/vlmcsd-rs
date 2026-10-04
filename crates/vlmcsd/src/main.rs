use std::{net::SocketAddr, num::NonZeroUsize, time::Duration};

use clap::Parser;
use tokio::net::TcpListener;
use vlmcsd::{HostConfig, ServerConfig, serve};

#[derive(Parser)]
#[command(version, about = "Async KMS V4/V5/V6 emulator")]
struct Args {
    #[arg(short = 'L', long, default_value = "127.0.0.1:1688")]
    listen: SocketAddr,
    #[arg(long, default_value = "256")]
    max_connections: NonZeroUsize,
    /// Deadline for one complete RPC exchange, in seconds.
    #[arg(long, default_value = "30", value_parser = clap::value_parser!(u64).range(1..))]
    timeout: u64,
    #[arg(long, default_value = "1024")]
    max_exchanges: NonZeroUsize,
    #[arg(long, default_value = "5")]
    shutdown_grace: u64,
    #[arg(long)]
    epid: Option<String>,
    /// Emulated client count (not a measured count).
    #[arg(long, default_value = "50")]
    client_count: u32,
    #[arg(long, default_value = "120")]
    activation_interval: u32,
    #[arg(long, default_value = "10080")]
    renewal_interval: u32,
    /// Eight-byte hardware ID, encoded as 16 hexadecimal digits.
    #[arg(long, value_parser = parse_hardware_id)]
    hardware_id: Option<[u8; 8]>,
}

fn parse_hardware_id(value: &str) -> Result<[u8; 8], String> {
    if value.len() != 16 || !value.is_ascii() {
        return Err("expected 16 hexadecimal digits".into());
    }
    let mut out = [0; 8];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "expected 16 hexadecimal digits")?;
    }
    Ok(out)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let mut host = HostConfig {
        client_count: args.client_count,
        activation_interval: args.activation_interval,
        renewal_interval: args.renewal_interval,
        ..HostConfig::default()
    };
    if let Some(epid) = args.epid {
        host.epid = epid;
    }
    if let Some(id) = args.hardware_id {
        host.hardware_id = id;
    }
    let config = ServerConfig {
        host,
        max_connections: args.max_connections,
        exchange_timeout: Duration::from_secs(args.timeout),
        max_exchanges: args.max_exchanges,
        shutdown_grace: Duration::from_secs(args.shutdown_grace),
    };
    // Register signals before accepting traffic so setup failures cannot be hidden.
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let shutdown = async move {
        #[cfg(unix)]
        tokio::select! {
            result = tokio::signal::ctrl_c() => { if let Err(error) = result { tracing::error!(%error, "signal handler failed"); } },
            _ = terminate.recv() => {},
        }
        #[cfg(not(unix))]
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "signal handler failed");
        }
    };
    let listener = TcpListener::bind(args.listen).await?;
    tracing::info!(address = %listener.local_addr()?, "KMS listener bound");
    serve(listener, config, shutdown).await?;
    Ok(())
}
