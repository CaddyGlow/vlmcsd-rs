//! Standard-library blocking server and individual connection handling.
//! Call these operations on dedicated threads in async applications.
//!
//! ```no_run
//! use std::{net::TcpListener, sync::atomic::AtomicBool};
//! # fn example() -> Result<(), vlmcsd::Error> {
//! let listener = TcpListener::bind("127.0.0.1:1688")?;
//! let shutdown = AtomicBool::new(false);
//! // Another thread sets this flag when shutdown is requested.
//! vlmcsd::blocking::serve(listener, vlmcsd::ServerConfig::default(), &shutdown)?;
//! # Ok(())
//! # }
//! ```
use crate::{
    Error, ServerConfig,
    rpc::{self, Assembly, Pdu, Session},
};
use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use vlmcsd_protocol::PreparedHost;

/// Serves connections using at most `max_connections` worker threads.
///
/// Set `shutdown` to true to stop accepting. Active workers drain for
/// `shutdown_grace`, then their sockets are shut down and every worker is joined.
/// The listener is owned by this function and switched to nonblocking mode.
/// Shutdown and capacity are polled at intervals of at most 10 ms.
/// Malformed connections are logged and closed without stopping the listener.
pub fn serve(
    listener: TcpListener,
    config: ServerConfig,
    shutdown: &AtomicBool,
) -> Result<(), Error> {
    validate(&config)?;
    let host = Arc::new(PreparedHost::new(&config.host)?);
    let config = Arc::new(config);
    let port = listener.local_addr()?.port();
    listener.set_nonblocking(true)?;
    let mut workers = Workers(Vec::new());
    while !shutdown.load(Ordering::Acquire) {
        workers.reap()?;
        if workers.0.len() >= config.max_connections.get() {
            thread::sleep(Duration::from_millis(10));
            continue;
        }
        match listener.accept() {
            Ok((mut socket, peer)) => {
                socket.set_nonblocking(false)?;
                let control = socket.try_clone()?;
                let cancel = Arc::new(AtomicBool::new(false));
                let worker_cancel = Arc::clone(&cancel);
                let config = Arc::clone(&config);
                let host = Arc::clone(&host);
                let handle = thread::Builder::new()
                    .name("vlmcsd-connection".into())
                    .spawn(move || {
                        if let Err(error) =
                            run_connection(&mut socket, port, &config, &host, Some(&worker_cancel))
                        {
                            tracing::debug!(%peer,%error,"connection closed");
                        }
                    })?;
                workers.0.push(Worker {
                    socket: control,
                    cancel,
                    handle: Some(handle),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10))
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    drop(listener);
    let deadline = Instant::now()
        .checked_add(config.shutdown_grace)
        .ok_or(Error::Config("shutdown grace exceeds clock range"))?;
    while !workers.0.is_empty() && Instant::now() < deadline {
        workers.reap()?;
        thread::sleep(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(10)),
        );
    }
    // Cancel pending I/O and shut down the sockets, then join all workers.
    workers.stop()
}

/// Serves one already accepted socket until EOF or its exchange budget is exhausted.
/// Every complete exchange has a deadline. The caller owns threading and shutdown.
pub fn serve_connection(stream: &mut TcpStream, config: &ServerConfig) -> Result<(), Error> {
    validate(config)?;
    let host = PreparedHost::new(&config.host)?;
    stream.set_nonblocking(false)?;
    run_connection(stream, stream.local_addr()?.port(), config, &host, None)
}
fn validate(config: &ServerConfig) -> Result<(), Error> {
    if config.exchange_timeout.is_zero() {
        return Err(Error::Config("exchange timeout must be nonzero"));
    }
    Instant::now()
        .checked_add(config.exchange_timeout)
        .ok_or(Error::Config("timeout exceeds clock range"))?;
    Instant::now()
        .checked_add(config.shutdown_grace)
        .ok_or(Error::Config("shutdown grace exceeds clock range"))?;
    Ok(())
}
fn run_connection(
    socket: &mut TcpStream,
    port: u16,
    config: &ServerConfig,
    host: &PreparedHost,
    cancel: Option<&AtomicBool>,
) -> Result<(), Error> {
    let mut session = Session::new(port);
    for _ in 0..config.max_exchanges.get() {
        let deadline = Instant::now()
            .checked_add(config.exchange_timeout)
            .ok_or(Error::Config("timeout exceeds clock range"))?;
        let mut stream = Deadline {
            stream: socket,
            deadline,
            cancel,
        };
        let Some(first) = receive(&mut stream)? else {
            return Ok(());
        };
        let mut assembly = Assembly::new(first)?;
        while !assembly.complete() {
            assembly.push(
                receive(&mut stream)?.ok_or(Error::Protocol("incomplete fragmented request"))?,
            )?;
        }
        let output = session.process(assembly.finish(), host)?;
        stream.write_all(&output).map_err(io_error)?;
    }
    Ok(())
}
fn receive(stream: &mut Deadline<'_>) -> Result<Option<Pdu>, Error> {
    let mut header = [0; 16];
    loop {
        match stream.read(&mut header[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(io_error(error)),
        }
    }
    stream.read_exact(&mut header[1..]).map_err(io_error)?;
    let (kind, flags, call, size) = rpc::parse_header(&header)?;
    let mut body = vec![0; size - 16];
    stream.read_exact(&mut body).map_err(io_error)?;
    Ok(Some(Pdu {
        kind,
        flags,
        call,
        body,
    }))
}

struct Worker {
    socket: TcpStream,
    cancel: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}
struct Workers(Vec<Worker>);
impl Workers {
    fn reap(&mut self) -> Result<(), Error> {
        let mut index = 0;
        while index < self.0.len() {
            if self.0[index]
                .handle
                .as_ref()
                .is_some_and(|h| h.is_finished())
            {
                let mut worker = self.0.swap_remove(index);
                worker
                    .handle
                    .take()
                    .unwrap()
                    .join()
                    .map_err(|_| Error::WorkerPanic)?;
            } else {
                index += 1;
            }
        }
        Ok(())
    }
    fn stop(&mut self) -> Result<(), Error> {
        for worker in &self.0 {
            worker.cancel.store(true, Ordering::Release);
            let _ = worker.socket.shutdown(Shutdown::Both);
        }
        let mut panicked = false;
        for mut worker in self.0.drain(..) {
            if let Some(handle) = worker.handle.take() {
                panicked |= handle.join().is_err();
            }
        }
        if panicked {
            Err(Error::WorkerPanic)
        } else {
            Ok(())
        }
    }
}
impl Drop for Workers {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

struct Deadline<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
    cancel: Option<&'a AtomicBool>,
}
impl Deadline<'_> {
    fn remaining(&self) -> std::io::Result<Duration> {
        if self.cancel.is_some_and(|flag| flag.load(Ordering::Acquire)) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "server stopped",
            ));
        }
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "exchange deadline expired")
            })
    }
    fn io_timeout(&self) -> std::io::Result<Duration> {
        let remaining = self.remaining()?;
        // Winsock shutdown may leave a blocking operation pending. Poll the
        // cancellation flag without shortening the complete exchange deadline.
        Ok(if self.cancel.is_some() {
            remaining.min(Duration::from_millis(50))
        } else {
            remaining
        })
    }
}
impl Read for Deadline<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        loop {
            self.stream.set_read_timeout(Some(self.io_timeout()?))?;
            match self.stream.read(bytes) {
                Err(error)
                    if self.cancel.is_some()
                        && matches!(
                            error.kind(),
                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                        ) => {}
                result => return result,
            }
        }
    }
}
impl Write for Deadline<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        loop {
            self.stream.set_write_timeout(Some(self.io_timeout()?))?;
            match self.stream.write(bytes) {
                Err(error)
                    if self.cancel.is_some()
                        && matches!(
                            error.kind(),
                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                        ) => {}
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}
fn io_error(error: std::io::Error) -> Error {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => Error::Timeout,
        _ => Error::Io(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_interrupts_pending_read_without_socket_shutdown() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let peer = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            // Wait across several polling intervals to verify that polling
            // timeouts do not become exchange timeouts.
            thread::sleep(Duration::from_millis(150));
            socket.write_all(&[42]).unwrap();
            thread::sleep(Duration::from_millis(150));
            worker_cancel.store(true, Ordering::Release);
            // Keep the socket open until the pending read has been canceled.
            socket
        });
        let mut socket = TcpStream::connect(address).unwrap();
        let mut stream = Deadline {
            stream: &mut socket,
            deadline: Instant::now() + Duration::from_secs(5),
            cancel: Some(&cancel),
        };
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [42]);
        let start = Instant::now();
        let error = stream.read(&mut byte).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
        assert!(start.elapsed() < Duration::from_secs(1));
        drop(peer.join().unwrap());
    }
}
