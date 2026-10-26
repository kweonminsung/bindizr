//! Plain DNS TCP listener and connection admission.

use std::future::Future;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::connection;
use super::error::DnsError;
use super::server::DnsContext;
use super::stream::DnsStream;
use crate::shutdown::Shutdown;

/// Accept plain DNS TCP connections until shutdown.
pub(crate) async fn run_tcp_server(
    dns_cx: Arc<DnsContext>,
    listener: TcpListener,
    stop: impl Future<Output = ()>,
) -> Result<(), DnsError> {
    // Separate listener budgets keep a full TCP port from blocking TLS.
    let open = Arc::new(Semaphore::new(
        dns_cx.daemon().config().dns.tcp_max_connections,
    ));
    tokio::pin!(stop);
    let connection_shutdown = Shutdown::new();
    let mut connections = JoinSet::new();

    let outcome = loop {
        // The slot comes before the accept, so the backlog holds the excess.
        let permit = tokio::select! {
            biased;
            () = &mut stop => break Ok(()),

            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    log::warn!("DNS TCP connection task failed: {}", error);
                }
                continue;
            }

            permit = open.clone().acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(error) => break Err(error.into()),
            },
        };

        let accepted = tokio::select! {
            biased;
            () = &mut stop => break Ok(()),

            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    log::warn!("DNS TCP connection task failed: {}", error);
                }
                continue;
            }

            accepted = listener.accept() => accepted,
        };

        match accepted {
            Ok((stream, client_addr)) => {
                let dns_cx = dns_cx.clone();
                let stop = connection_shutdown.waiter();

                connections.spawn(async move {
                    let _permit = permit;

                    if let Err(error) = connection::serve_connection(
                        dns_cx,
                        DnsStream::Tcp(stream),
                        client_addr,
                        stop,
                    )
                    .await
                    {
                        log::error!(
                            "Failed to read DNS TCP message from {}: {}",
                            client_addr,
                            error
                        );
                    }
                });
            }
            Err(error) => {
                log::error!("Failed to accept DNS TCP connection: {}", error);
            }
        }
    };

    // Stop accepting before asking existing connections to drain.
    drop(listener);
    connection_shutdown.trigger();

    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            log::warn!("DNS TCP connection task failed: {}", error);
        }
    }

    log::info!("DNS TCP server stopped");

    outcome
}
