use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
};
use vlmcs::{ActivationRequest, Client, ClientConfig, Error, Version};

#[tokio::test]
async fn versions_syntaxes_repeated_requests_and_cli() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, done) = oneshot::channel();
    let server = tokio::spawn(vlmcsd::serve(
        listener,
        vlmcsd::ServerConfig::default(),
        async {
            let _ = done.await;
        },
    ));
    for ndr64 in [false, true] {
        let mut client = Client::connect(
            address,
            ClientConfig {
                ndr64,
                ..ClientConfig::default()
            },
        )
        .await
        .unwrap();
        for version in [Version::V4, Version::V5, Version::V6] {
            let mut request =
                ActivationRequest::new([1; 16], [2; 16], [3; 16], [4; 16], 133444736000000000);
            request.version = version;
            for _ in 0..2 {
                let response = client.activate(&request).await.unwrap();
                assert_eq!(response.version, version);
                assert_eq!(response.client_count, 50);
                assert_eq!(response.activation_interval, 120);
                assert_eq!(response.renewal_interval, 10080);
            }
        }
    }
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_vlmcs"))
        .args(["-6", "-n", "2", "--ndr64", &address.to_string()])
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout)
            .matches("ePID:")
            .count(),
        2
    );
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn bind_timeout_and_invalid_call_id_fail() {
    for corrupt in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bind = [0; 72];
            socket.read_exact(&mut bind).await.unwrap();
            if corrupt {
                let header = [5, 0, 12, 3, 0x10, 0, 0, 0, 16, 0, 0, 0, 99, 0, 0, 0];
                socket.write_all(&header).await.unwrap();
            } else {
                std::future::pending::<()>().await;
            }
        });
        let error = Client::connect(
            address,
            ClientConfig {
                timeout: Duration::from_millis(100),
                ..ClientConfig::default()
            },
        )
        .await
        .err()
        .unwrap();
        if corrupt {
            assert!(matches!(error, Error::Protocol(_)));
        } else {
            assert!(matches!(error, Error::Timeout));
        }
        peer.abort();
        let _ = peer.await;
    }
}

#[tokio::test]
async fn cli_rejects_invalid_inputs() {
    for args in [
        vec!["-n", "0"],
        vec!["-t", "0"],
        vec!["-4", "-6"],
        vec!["--application-id", "nope"],
        vec!["--unknown"],
    ] {
        let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_vlmcs"))
            .args(args)
            .output()
            .await
            .unwrap();
        assert!(!output.status.success());
    }
}

async fn frame(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut header = [0; 16];
    socket.read_exact(&mut header).await.unwrap();
    let size = usize::from(u16::from_le_bytes([header[8], header[9]]));
    let mut packet = header.to_vec();
    packet.resize(size, 0);
    socket.read_exact(&mut packet[16..]).await.unwrap();
    packet
}

#[tokio::test]
async fn fragmented_responses_errors_and_cancellation() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_address = listener.local_addr().unwrap();
    let (stop, done) = oneshot::channel();
    let server = tokio::spawn(vlmcsd::serve(
        listener,
        vlmcsd::ServerConfig::default(),
        async {
            let _ = done.await;
        },
    ));
    for mode in [
        "fragmented",
        "context",
        "length",
        "fault",
        "status",
        "timeout",
        "cancel",
    ] {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = proxy.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut downstream, _) = proxy.accept().await.unwrap();
            let mut upstream = tokio::net::TcpStream::connect(server_address)
                .await
                .unwrap();
            upstream
                .write_all(&frame(&mut downstream).await)
                .await
                .unwrap();
            downstream
                .write_all(&frame(&mut upstream).await)
                .await
                .unwrap();
            upstream
                .write_all(&frame(&mut downstream).await)
                .await
                .unwrap();
            let mut response = frame(&mut upstream).await;
            match mode {
                "timeout" | "cancel" => std::future::pending::<()>().await,
                "fragmented" => {
                    let mut first = response[..65].to_vec();
                    first[3] = 1;
                    first[8..10].copy_from_slice(&65u16.to_le_bytes());
                    let mut last = response[..24].to_vec();
                    last.extend_from_slice(&response[65..]);
                    last[3] = 2;
                    let size = last.len() as u16;
                    last[8..10].copy_from_slice(&size.to_le_bytes());
                    downstream.write_all(&first).await.unwrap();
                    downstream.write_all(&last).await.unwrap();
                    return;
                }
                "context" => response[20] = 1,
                "length" => response[24] ^= 1,
                "fault" => {
                    response.truncate(32);
                    response[2] = 3;
                    response[8..10].copy_from_slice(&32u16.to_le_bytes());
                    response[24..28].copy_from_slice(&0x1c010002u32.to_le_bytes());
                }
                "status" => {
                    let end = response.len();
                    response[end - 4..].copy_from_slice(&0x8007000du32.to_le_bytes());
                }
                _ => unreachable!(),
            }
            downstream.write_all(&response).await.unwrap();
        });
        let mut client = Client::connect(
            address,
            ClientConfig {
                timeout: Duration::from_millis(200),
                ..ClientConfig::default()
            },
        )
        .await
        .unwrap();
        let request =
            ActivationRequest::new([1; 16], [2; 16], [3; 16], [4; 16], 133444736000000000);
        if mode == "cancel" {
            assert!(
                tokio::time::timeout(Duration::from_millis(20), client.activate(&request))
                    .await
                    .is_err()
            );
            assert!(matches!(
                client.activate(&request).await,
                Err(Error::Closed)
            ));
        } else {
            let result = client.activate(&request).await;
            match mode {
                "fragmented" => {
                    assert_eq!(result.unwrap().client_count, 50);
                }
                "timeout" => assert!(matches!(result, Err(Error::Timeout))),
                "fault" => assert!(matches!(result, Err(Error::Status(0x1c010002)))),
                "status" => assert!(matches!(result, Err(Error::Status(0x8007000d)))),
                _ => assert!(matches!(result, Err(Error::Protocol(_)))),
            }
            if mode != "fragmented" {
                assert!(matches!(
                    client.activate(&request).await,
                    Err(Error::Closed)
                ));
            }
        }
        task.abort();
        let _ = task.await;
    }
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}
