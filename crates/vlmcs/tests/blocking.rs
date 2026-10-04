use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use vlmcs::{ActivationRequest, ClientConfig, Error, Version, blocking::Client};

struct Server {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    task: Option<JoinHandle<Result<(), vlmcsd::Error>>>,
}
impl Server {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::clone(&stop);
        let task = thread::spawn(move || {
            vlmcsd::blocking::serve(
                listener,
                vlmcsd::ServerConfig {
                    shutdown_grace: Duration::from_millis(50),
                    ..Default::default()
                },
                &shutdown,
            )
        });
        Self {
            address,
            stop,
            task: Some(task),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.task.take().unwrap().join().unwrap().unwrap();
    }
}
fn request(version: Version) -> ActivationRequest {
    let mut request =
        ActivationRequest::new([1; 16], [2; 16], [3; 16], [4; 16], 133444736000000000);
    request.version = version;
    request
}
#[test]
fn blocking_client_and_server_all_versions_and_syntaxes() {
    let server = Server::start();
    for ndr64 in [false, true] {
        let mut client = Client::connect(
            server.address,
            ClientConfig {
                ndr64,
                ..Default::default()
            },
        )
        .unwrap();
        for version in [Version::V4, Version::V5, Version::V6] {
            for _ in 0..2 {
                let response = client.activate(&request(version)).unwrap();
                assert_eq!(response.version, version);
                assert_eq!(response.client_count, 50);
            }
        }
    }
}
#[cfg(feature = "async")]
#[tokio::test]
async fn async_client_to_blocking_server() {
    let server = Server::start();
    for ndr64 in [false, true] {
        let mut client = vlmcs::Client::connect(
            server.address,
            ClientConfig {
                ndr64,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        for version in [Version::V4, Version::V5, Version::V6] {
            assert_eq!(
                client
                    .activate(&request(version))
                    .await
                    .unwrap()
                    .client_count,
                50
            );
        }
    }
}
#[cfg(feature = "async")]
#[tokio::test]
async fn blocking_client_to_async_server() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, receive) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(vlmcsd::serve(listener, Default::default(), async {
        let _ = receive.await;
    }));
    tokio::task::spawn_blocking(move || {
        for ndr64 in [false, true] {
            let mut client = Client::connect(
                address,
                ClientConfig {
                    ndr64,
                    ..Default::default()
                },
            )
            .unwrap();
            for version in [Version::V4, Version::V5, Version::V6] {
                assert_eq!(client.activate(&request(version)).unwrap().client_count, 50);
            }
        }
    })
    .await
    .unwrap();
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}
#[test]
fn deadline_covers_bytewise_header_delivery() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut bind = [0; 72];
        stream.read_exact(&mut bind).unwrap();
        for byte in [5, 0, 12, 3, 0x10, 0, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0] {
            if stream.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    });
    let start = Instant::now();
    let error = Client::connect(
        address,
        ClientConfig {
            timeout: Duration::from_millis(80),
            ..Default::default()
        },
    )
    .err()
    .unwrap();
    assert!(matches!(error, Error::Timeout));
    assert!(start.elapsed() < Duration::from_millis(250));
    peer.join().unwrap();
}
#[test]
fn validation_precedes_connect() {
    assert!(matches!(
        Client::connect(
            "127.0.0.1:0",
            ClientConfig {
                timeout: Duration::ZERO,
                ..Default::default()
            }
        ),
        Err(Error::Config(_))
    ));
    let server = Server::start();
    let mut client = Client::connect(server.address, Default::default()).unwrap();
    let mut invalid = request(Version::V6);
    invalid.workstation = "x".repeat(64);
    assert!(matches!(client.activate(&invalid), Err(Error::Codec(_))));
    assert_eq!(
        client.activate(&request(Version::V6)).unwrap().client_count,
        50
    );
}

fn frame(stream: &mut std::net::TcpStream) -> Vec<u8> {
    let mut header = [0; 16];
    stream.read_exact(&mut header).unwrap();
    let size = usize::from(u16::from_le_bytes([header[8], header[9]]));
    let mut out = header.to_vec();
    out.resize(size, 0);
    stream.read_exact(&mut out[16..]).unwrap();
    out
}
#[test]
fn fragmented_response_fault_and_request_timeout() {
    let server = Server::start();
    for mode in ["fragmented", "fault", "timeout"] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let upstream_address = server.address;
        let proxy = thread::spawn(move || {
            let (mut downstream, _) = listener.accept().unwrap();
            let mut upstream = std::net::TcpStream::connect(upstream_address).unwrap();
            upstream.write_all(&frame(&mut downstream)).unwrap();
            downstream.write_all(&frame(&mut upstream)).unwrap();
            upstream.write_all(&frame(&mut downstream)).unwrap();
            let mut response = frame(&mut upstream);
            match mode {
                "fragmented" => {
                    let mut first = response[..65].to_vec();
                    first[3] = 1;
                    first[8..10].copy_from_slice(&65u16.to_le_bytes());
                    let mut last = response[..24].to_vec();
                    last.extend_from_slice(&response[65..]);
                    last[3] = 2;
                    let size = last.len() as u16;
                    last[8..10].copy_from_slice(&size.to_le_bytes());
                    downstream.write_all(&first).unwrap();
                    downstream.write_all(&last).unwrap();
                }
                "fault" => {
                    response.truncate(32);
                    response[2] = 3;
                    response[8..10].copy_from_slice(&32u16.to_le_bytes());
                    response[24..28].copy_from_slice(&0x1c010002u32.to_le_bytes());
                    downstream.write_all(&response).unwrap();
                }
                "timeout" => thread::sleep(Duration::from_millis(200)),
                _ => unreachable!(),
            }
        });
        let mut client = Client::connect(
            address,
            ClientConfig {
                timeout: Duration::from_millis(100),
                ..Default::default()
            },
        )
        .unwrap();
        let result = client.activate(&request(Version::V6));
        match mode {
            "fragmented" => assert_eq!(result.unwrap().client_count, 50),
            "fault" => assert!(matches!(result, Err(Error::Status(0x1c010002)))),
            "timeout" => assert!(matches!(result, Err(Error::Timeout))),
            _ => unreachable!(),
        }
        if mode != "fragmented" {
            assert!(matches!(
                client.activate(&request(Version::V6)),
                Err(Error::Closed)
            ));
        }
        proxy.join().unwrap();
    }
}
