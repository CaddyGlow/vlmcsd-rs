use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use vlmcsd::ServerConfig;

struct Server {
    address: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    task: Option<JoinHandle<Result<(), vlmcsd::Error>>>,
}
impl Server {
    fn start(config: ServerConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::clone(&stop);
        let task = thread::spawn(move || vlmcsd::blocking::serve(listener, config, &shutdown));
        Self {
            address,
            stop,
            task: Some(task),
        }
    }
    fn connect(&self) -> TcpStream {
        let socket = TcpStream::connect(self.address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
    }
    fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.task.take().unwrap().join().unwrap().unwrap();
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if self.task.is_some() {
            self.stop();
        }
    }
}
fn bind() -> Vec<u8> {
    let mut out = vec![
        5, 0, 11, 3, 0x10, 0, 0, 0, 72, 0, 0, 0, 1, 0, 0, 0, 0, 16, 0, 16, 0, 0, 0, 0, 1, 0, 0, 0,
        0, 0, 1, 0,
    ];
    out.extend_from_slice(&[
        0x75, 0x21, 0xc8, 0x51, 0x4e, 0x84, 0x50, 0x47, 0xb0, 0xd8, 0xec, 0x25, 0x55, 0x55, 0xbc,
        0x06, 1, 0, 0, 0,
    ]);
    out.extend_from_slice(&[
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48,
        0x60, 2, 0, 0, 0,
    ]);
    out
}
fn ack(socket: &mut TcpStream) {
    let mut header = [0; 16];
    socket.read_exact(&mut header).unwrap();
    assert_eq!(header[2], 12);
    let len = usize::from(u16::from_le_bytes([header[8], header[9]]));
    let mut body = vec![0; len - 16];
    socket.read_exact(&mut body).unwrap();
}
fn closed(socket: &mut TcpStream) {
    let result = socket.read(&mut [0]);
    assert!(
        matches!(result, Ok(0))
            || matches!(result,Err(ref e) if e.kind()!=std::io::ErrorKind::WouldBlock && e.kind()!=std::io::ErrorKind::TimedOut),
        "{result:?}"
    );
}
#[test]
fn capacity_released_and_shutdown_interrupts_idle_workers() {
    let mut server = Server::start(ServerConfig {
        max_connections: NonZeroUsize::MIN,
        shutdown_grace: Duration::from_millis(30),
        ..Default::default()
    });
    let mut first = server.connect();
    first.write_all(&bind()).unwrap();
    ack(&mut first);
    let mut second = server.connect();
    second.write_all(&bind()).unwrap();
    second
        .set_read_timeout(Some(Duration::from_millis(40)))
        .unwrap();
    assert!(second.read(&mut [0]).is_err());
    drop(first);
    second
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    ack(&mut second);
    let start = Instant::now();
    server.stop();
    assert!(start.elapsed() < Duration::from_secs(1));
    closed(&mut second);
}
#[test]
fn timeout_and_budget_close_connections() {
    let server = Server::start(ServerConfig {
        exchange_timeout: Duration::from_millis(60),
        max_exchanges: NonZeroUsize::MIN,
        ..Default::default()
    });
    let mut stalled = server.connect();
    stalled.write_all(&[5]).unwrap();
    closed(&mut stalled);
    let mut bound = server.connect();
    bound.write_all(&bind()).unwrap();
    ack(&mut bound);
    closed(&mut bound);
}
#[test]
fn malformed_peer_does_not_stop_listener() {
    let server = Server::start(Default::default());
    let mut malformed = server.connect();
    let mut packet = bind();
    packet[0] = 4;
    malformed.write_all(&packet).unwrap();
    closed(&mut malformed);
    let mut healthy = server.connect();
    healthy.write_all(&bind()).unwrap();
    ack(&mut healthy);
}
#[test]
fn serve_connection_and_configuration_validation() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        vlmcsd::blocking::serve_connection(
            &mut socket,
            &ServerConfig {
                max_exchanges: NonZeroUsize::MIN,
                ..Default::default()
            },
        )
        .unwrap();
    });
    let mut socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket.write_all(&bind()).unwrap();
    ack(&mut socket);
    closed(&mut socket);
    worker.join().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    assert!(matches!(
        vlmcsd::blocking::serve(
            listener,
            ServerConfig {
                exchange_timeout: Duration::ZERO,
                ..Default::default()
            },
            &AtomicBool::new(false)
        ),
        Err(vlmcsd::Error::Config(_))
    ));
}
