// Async adaptation of mingtsay/vlmcsd-rs network/tests/integration.rs.
// See THIRD-PARTY-NOTICES. Requests and expected responses come from py-kms.
use std::{num::NonZeroUsize, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};
use vlmcsd::{ServerConfig, serve};

const V4: &[u8] = include_bytes!("../../../tests/fixtures/v4-request.bin");
const V5: &[u8] = include_bytes!("../../../tests/fixtures/v5-request.bin");
const V6: &[u8] = include_bytes!("../../../tests/fixtures/v6-request.bin");
const INTERFACE: [u8; 16] = [
    0x75, 0x21, 0xc8, 0x51, 0x4e, 0x84, 0x50, 0x47, 0xb0, 0xd8, 0xec, 0x25, 0x55, 0x55, 0xbc, 0x06,
];
const NDR32: [u8; 16] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
];
const NDR64: [u8; 16] = [
    0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36,
];

struct Server {
    address: std::net::SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), vlmcsd::Error>>,
}

impl Server {
    async fn start(config: ServerConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, receive) = oneshot::channel();
        let task = tokio::spawn(serve(listener, config, async {
            let _ = receive.await;
        }));
        Self {
            address,
            stop: Some(stop),
            task,
        }
    }
    async fn connect(&self) -> TcpStream {
        TcpStream::connect(self.address).await.unwrap()
    }
    async fn stop(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        timeout(Duration::from_secs(2), &mut self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn packet(kind: u8, flags: u8, call: u32, body: &[u8]) -> Vec<u8> {
    let mut out = vec![5, 0, kind, flags, 0x10, 0, 0, 0];
    out.extend_from_slice(&((body.len() + 16) as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&call.to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn bind(ndr64: bool) -> Vec<u8> {
    let mut out = vec![];
    out.extend_from_slice(&4096u16.to_le_bytes());
    out.extend_from_slice(&4096u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&7u16.to_le_bytes());
    out.extend_from_slice(&[1, 0]);
    out.extend_from_slice(&INTERFACE);
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&if ndr64 { NDR64 } else { NDR32 });
    out.extend_from_slice(&(if ndr64 { 1u32 } else { 2 }).to_le_bytes());
    packet(11, 0x13, 1, &out)
}

fn request(raw: &[u8], ndr64: bool) -> Vec<u8> {
    let mut out = vec![];
    let width = if ndr64 { 8 } else { 4 };
    out.extend_from_slice(&((raw.len() + width * 2) as u32).to_le_bytes());
    out.extend_from_slice(&7u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    for _ in 0..2 {
        out.extend_from_slice(&(raw.len() as u64).to_le_bytes()[..width]);
    }
    out.extend_from_slice(raw);
    out
}

async fn receive(stream: &mut TcpStream) -> (Vec<u8>, Vec<u8>) {
    timeout(Duration::from_secs(2), async {
        let mut header = vec![0; 16];
        stream.read_exact(&mut header).await.unwrap();
        let len = usize::from(u16::from_le_bytes([header[8], header[9]]));
        assert!((16..=4096).contains(&len));
        let mut body = vec![0; len - 16];
        stream.read_exact(&mut body).await.unwrap();
        (header, body)
    })
    .await
    .unwrap()
}

async fn handshake(stream: &mut TcpStream, ndr64: bool) {
    stream.write_all(&bind(ndr64)).await.unwrap();
    let (header, ack) = receive(stream).await;
    assert_eq!(header[2], 12);
    assert_eq!(header[3], 0x13);
    let address_len = usize::from(u16::from_le_bytes([ack[8], ack[9]]));
    let result = (10 + address_len).next_multiple_of(4) + 4;
    assert_eq!(&ack[result..result + 4], &[0; 4]);
}

async fn assert_closed(stream: &mut TcpStream) {
    let result = timeout(Duration::from_secs(2), stream.read(&mut [0]))
        .await
        .unwrap();
    assert!(matches!(result, Ok(0)) || result.is_err(), "{result:?}");
}

#[tokio::test]
async fn upstream_v4_v5_v6_roundtrips_over_both_transfer_syntaxes() {
    let server = Server::start(ServerConfig::default()).await;
    for ndr64 in [false, true] {
        let mut stream = server.connect().await;
        handshake(&mut stream, ndr64).await;
        for (index, raw) in [V4, V5, V6].into_iter().enumerate() {
            let call = index as u32 + 2;
            stream
                .write_all(&packet(0, 3, call, &request(raw, ndr64)))
                .await
                .unwrap();
            let (header, body) = receive(&mut stream).await;
            assert_eq!(header[2], 2);
            assert_eq!(&header[12..], &call.to_le_bytes());
            let width = if ndr64 { 8 } else { 4 };
            let length = u32::from_le_bytes(body[8..12].try_into().unwrap()) as usize;
            let response = &body[8 + 3 * width..8 + 3 * width + length];
            assert_eq!(&response[..4], &raw[..4]);
            assert_eq!(&body[body.len() - 4..], &[0; 4]);
            if index == 0 {
                assert_eq!(
                    response,
                    include_bytes!("../../../tests/fixtures/v4-response.bin")
                );
            }
        }
        drop(stream);
    }
    server.stop().await;
}

#[tokio::test]
async fn fragmented_requests_and_bytewise_tcp_delivery_work() {
    let server = Server::start(ServerConfig::default()).await;
    let mut stream = server.connect().await;
    for byte in bind(false) {
        stream.write_all(&[byte]).await.unwrap();
    }
    receive(&mut stream).await;
    let body = request(V4, false);
    stream
        .write_all(&packet(0, 1, 2, &body[..105]))
        .await
        .unwrap();
    let mut last = body[..8].to_vec();
    last.extend_from_slice(&body[105..]);
    stream.write_all(&packet(0, 2, 2, &last)).await.unwrap();
    let (_, response) = receive(&mut stream).await;
    assert_eq!(
        &response[20..20 + include_bytes!("../../../tests/fixtures/v4-response.bin").len()],
        include_bytes!("../../../tests/fixtures/v4-response.bin")
    );
    drop(stream);
    server.stop().await;
}

#[tokio::test]
async fn unknown_context_and_operation_return_faults_without_losing_connection() {
    let server = Server::start(ServerConfig::default()).await;
    let mut stream = server.connect().await;
    handshake(&mut stream, false).await;
    for (offset, status) in [(4, 0x1c00001cu32), (6, 0x1c010002u32)] {
        let mut body = request(V4, false);
        body[offset] = 99;
        stream.write_all(&packet(0, 3, 2, &body)).await.unwrap();
        let (header, fault) = receive(&mut stream).await;
        assert_eq!(header[2], 3);
        assert_eq!(&fault[8..12], &status.to_le_bytes());
    }
    stream
        .write_all(&packet(0, 3, 3, &request(V4, false)))
        .await
        .unwrap();
    assert_eq!(receive(&mut stream).await.0[2], 2);
    drop(stream);
    server.stop().await;
}

#[tokio::test]
async fn malformed_headers_close_only_the_offending_connection() {
    let server = Server::start(ServerConfig::default()).await;
    for (offset, value) in [(0, 4), (3, 0x83), (4, 0), (8, 0), (9, 255), (10, 1)] {
        let mut stream = server.connect().await;
        let mut header = packet(0, 3, 1, &[]);
        header[offset] = value;
        stream.write_all(&header).await.unwrap();
        assert_closed(&mut stream).await;
    }
    let mut healthy = server.connect().await;
    handshake(&mut healthy, false).await;
    drop(healthy);
    server.stop().await;
}

#[tokio::test]
async fn inconsistent_ndr_lengths_and_unbound_requests_are_rejected() {
    let server = Server::start(ServerConfig::default()).await;
    let mut stream = server.connect().await;
    stream
        .write_all(&packet(0, 3, 1, &request(V4, false)))
        .await
        .unwrap();
    assert_closed(&mut stream).await;
    for ndr64 in [false, true] {
        let mut stream = server.connect().await;
        handshake(&mut stream, ndr64).await;
        let mut body = request(V4, ndr64);
        body[8] ^= 1;
        stream.write_all(&packet(0, 3, 2, &body)).await.unwrap();
        assert_closed(&mut stream).await;
    }
    server.stop().await;
}

#[tokio::test]
async fn connection_limit_applies_backpressure_and_releases_capacity() {
    let config = ServerConfig {
        max_connections: NonZeroUsize::MIN,
        ..ServerConfig::default()
    };
    let server = Server::start(config).await;
    let mut first = server.connect().await;
    handshake(&mut first, false).await;
    let mut second = server.connect().await;
    second.write_all(&bind(false)).await.unwrap();
    assert!(
        timeout(Duration::from_millis(40), second.read(&mut [0]))
            .await
            .is_err()
    );
    drop(first);
    assert_eq!(receive(&mut second).await.0[2], 12);
    drop(second);
    server.stop().await;
}

#[tokio::test]
async fn stalled_partial_header_expires() {
    let config = ServerConfig {
        exchange_timeout: Duration::from_millis(50),
        ..ServerConfig::default()
    };
    let server = Server::start(config).await;
    let mut stream = server.connect().await;
    stream.write_all(&[5]).await.unwrap();
    assert_closed(&mut stream).await;
    server.stop().await;
}

#[tokio::test]
async fn shutdown_aborts_and_joins_idle_connections_after_grace() {
    let config = ServerConfig {
        shutdown_grace: Duration::ZERO,
        ..ServerConfig::default()
    };
    let server = Server::start(config).await;
    let mut stream = server.connect().await;
    handshake(&mut stream, false).await;
    server.stop().await;
    assert_closed(&mut stream).await;
}

#[tokio::test]
async fn exchange_budget_closes_persistent_connection() {
    let config = ServerConfig {
        max_exchanges: NonZeroUsize::MIN,
        ..ServerConfig::default()
    };
    let server = Server::start(config).await;
    let mut stream = server.connect().await;
    handshake(&mut stream, false).await;
    assert_closed(&mut stream).await;
    server.stop().await;
}

#[tokio::test]
async fn invalid_configuration_fails_before_accepting() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = ServerConfig {
        exchange_timeout: Duration::ZERO,
        ..ServerConfig::default()
    };
    assert!(matches!(
        serve(listener, config, std::future::pending()).await,
        Err(vlmcsd::Error::Config(_))
    ));
}

#[tokio::test]
#[ignore = "requires PYKMS_SOURCE pointing to a py-kms checkout and python3"]
async fn python_reference_validates_all_versions_syntaxes_and_fragmentation() {
    let source = std::env::var_os("PYKMS_SOURCE").expect("set PYKMS_SOURCE to the py-kms checkout");
    let server = Server::start(ServerConfig::default()).await;
    let output = timeout(
        Duration::from_secs(30),
        tokio::process::Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../scripts/pykms_interop.py"
            ))
            .arg("--source")
            .arg(source)
            .arg("--connect")
            .arg(server.address.to_string())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| line.starts_with("PASS "))
            .count(),
        12
    );
    server.stop().await;
}

#[tokio::test]
#[ignore = "requires VLMC_CLIENT pointing to the independent C vlmcs executable"]
async fn c_reference_validates_all_versions_and_transfer_syntaxes() {
    let executable =
        std::env::var_os("VLMC_CLIENT").expect("set VLMC_CLIENT to the C vlmcs executable");
    let server = Server::start(ServerConfig::default()).await;
    for version in ["-4", "-5", "-6"] {
        for ndr64 in ["0", "1"] {
            let output = timeout(
                Duration::from_secs(15),
                tokio::process::Command::new(&executable)
                    .args([version, "-n", "2", "-N", ndr64, "-B", "0", "-v"])
                    .arg(server.address.to_string())
                    .kill_on_drop(true)
                    .output(),
            )
            .await
            .unwrap()
            .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                output.status.success(),
                "{version} NDR64={ndr64}\n{stdout}\n{stderr}"
            );
            assert_eq!(
                stdout.matches("Response from KMS server").count(),
                2,
                "{stdout}\n{stderr}"
            );
            // vlmcs reports some integrity failures as diagnostics without a failing exit code.
            for line in stdout.lines().chain(stderr.lines()) {
                let lower = line.to_ascii_lowercase();
                if lower.contains("warning") || lower.contains("error") || lower.contains("failed")
                {
                    assert!(
                        line.contains("NDR64 but no BTFN"),
                        "unexpected diagnostic: {line}"
                    );
                }
            }
        }
    }
    server.stop().await;
}
