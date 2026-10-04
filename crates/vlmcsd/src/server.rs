use std::{future::Future, sync::Arc};

use tokio::{net::TcpListener, task::JoinSet, time::timeout};

use crate::ServerConfig;
use crate::{Error, rpc::Session};
use vlmcsd_protocol::PreparedHost;

/// Serves a bound listener until `shutdown` resolves or the listener fails.
///
/// At capacity, accept is paused and the kernel's bounded listen backlog supplies
/// backpressure. All tasks are owned by the server; cancellation drops the task
/// set, and explicit shutdown drains it up to the grace period, then aborts and
/// joins remaining tasks. A malformed peer only closes its own connection.
pub async fn serve(
    listener: TcpListener,
    config: ServerConfig,
    shutdown: impl Future<Output = ()>,
) -> Result<(), Error> {
    let host = Arc::new(PreparedHost::new(&config.host)?);
    if config.exchange_timeout.is_zero() {
        return Err(Error::Config("exchange timeout must be nonzero"));
    }
    let port = listener.local_addr()?.port();
    let config = Arc::new(config);
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(result) = result { result?; }
            }
            accepted = listener.accept(), if tasks.len() < config.max_connections.get() => {
                let (mut stream, peer) = accepted?;
                let config = Arc::clone(&config);
                let host = Arc::clone(&host);
                tasks.spawn(async move {
                    let mut session = Session::new(port);
                    for _ in 0..config.max_exchanges.get() {
                        match timeout(config.exchange_timeout, session.exchange(&mut stream, &host)).await {
                            Ok(Ok(true)) => {},
                            Ok(Ok(false)) => break,
                            Ok(Err(error)) => {
                                tracing::debug!(%peer, %error, "connection closed");
                                break;
                            }
                            Err(_) => {
                                tracing::debug!(%peer, "connection deadline expired");
                                break;
                            }
                        }
                    }
                });
            }
        }
    }
    drop(listener);
    let drained = timeout(config.shutdown_grace, async {
        while let Some(result) = tasks.join_next().await {
            result?;
        }
        Ok::<_, Error>(())
    })
    .await;
    match drained {
        Ok(result) => result,
        Err(_) => {
            tasks.shutdown().await;
            Ok(())
        }
    }
}
