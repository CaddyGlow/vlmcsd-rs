use clap::Parser;
use std::{
    num::NonZeroU32,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use vlmcs::{ActivationRequest, Client, ClientConfig, Version};

#[derive(Parser)]
#[command(version, about = "Async KMS V4/V5/V6 test client")]
struct Args {
    /// Server hostname or IP, optionally with a port. IPv6 ports require brackets.
    #[arg(default_value = "127.0.0.1:1688")]
    host: String,
    #[arg(short = '4', conflicts_with_all = ["v5", "v6"])]
    v4: bool,
    #[arg(short = '5', conflicts_with_all = ["v4", "v6"])]
    v5: bool,
    #[arg(short = '6', conflicts_with_all = ["v4", "v5"])]
    v6: bool,
    /// Number of requests on one connection.
    #[arg(short = 'n', long, default_value = "1")]
    requests: NonZeroU32,
    #[arg(short = 'w', long, default_value = "WORKSTATION")]
    workstation: String,
    /// Deadline per complete exchange, in seconds.
    #[arg(short = 't', long, default_value = "30", value_parser = clap::value_parser!(u64).range(1..))]
    timeout: u64,
    #[arg(long)]
    ndr64: bool,
    #[arg(short, long)]
    verbose: bool,
    /// Application GUID (default: Windows).
    #[arg(long, default_value = "55c92734-d682-4d71-983e-d6ec3f16059f", value_parser = guid)]
    application_id: [u8; 16],
    /// Activation GUID (default: Windows Professional).
    #[arg(long, default_value = "2de67392-b7a7-462a-b1ca-108dd189f588", value_parser = guid)]
    activation_id: [u8; 16],
    /// Counted product GUID (default: Windows Professional).
    #[arg(long, default_value = "58e2134f-8e11-4d17-9cb2-91069c151148", value_parser = guid)]
    kms_id: [u8; 16],
    #[arg(long, default_value = "25")]
    required_count: u32,
}

fn guid(value: &str) -> Result<[u8; 16], String> {
    if value.len() != 36
        || !value.is_ascii()
        || [8, 13, 18, 23]
            .into_iter()
            .any(|i| value.as_bytes()[i] != b'-')
    {
        return Err("expected GUID xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".into());
    }
    let hex: String = value.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err("invalid GUID".into());
    }
    let mut out = [0; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|_| "invalid GUID hex")?;
    }
    out[..4].reverse();
    out[4..6].reverse();
    out[6..8].reverse();
    Ok(out)
}
fn endpoint(host: &str) -> String {
    if host.parse::<std::net::IpAddr>().is_ok() {
        if host.contains(':') {
            format!("[{host}]:1688")
        } else {
            format!("{host}:1688")
        }
    } else if host.ends_with(']') || !host.contains(':') {
        format!("{host}:1688")
    } else {
        host.into()
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut cmid = [0; 16];
    getrandom::fill(&mut cmid).map_err(|e| vlmcs::Error::Random(e.to_string()))?;
    cmid[7] = (cmid[7] & 15) | 0x40;
    cmid[8] = (cmid[8] & 63) | 0x80;
    let ticks = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() / 100
        + 116_444_736_000_000_000u128;
    let mut request = ActivationRequest::new(
        args.application_id,
        args.activation_id,
        args.kms_id,
        cmid,
        u64::try_from(ticks)?,
    );
    request.version = if args.v4 {
        Version::V4
    } else if args.v5 {
        Version::V5
    } else {
        Version::V6
    };
    request.workstation = args.workstation;
    request.required_count = args.required_count;
    // Validate local fields before establishing a connection.
    request.encode([0; 16])?;
    let mut client = Client::connect(
        endpoint(&args.host),
        ClientConfig {
            timeout: Duration::from_secs(args.timeout),
            ndr64: args.ndr64,
        },
    )
    .await?;
    for index in 1..=args.requests.get() {
        let response = client.activate(&request).await?;
        println!(
            "Response {index}: KMS V{}\nePID: {}\nClient Count: {}\nVL Activation Interval: {} minutes\nVL Renewal Interval: {} minutes",
            response.version.major(),
            response.epid,
            response.client_count,
            response.activation_interval,
            response.renewal_interval
        );
        if args.verbose {
            println!("CMID (wire bytes): {:02x?}", request.cmid);
            if let Some(id) = response.hardware_id {
                println!("Hardware ID: {:02x?}", id);
            }
        }
    }
    Ok(())
}
