//! Plain DNS TCP listener and connection admission.

use std::{future::Future, sync::Arc};

use tokio::{net::TcpListener, sync::Semaphore};

use super::{connection::serve_connection, error::DnsError, server::DnsContext, stream::DnsStream};

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

    loop {
        // The slot comes before the accept, so the backlog holds the excess.
        let permit = tokio::select! {
            permit = open.clone().acquire_owned() => permit?,
            () = &mut stop => {
                log::info!("DNS TCP server stopping");
                return Ok(());
            }
        };

        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            () = &mut stop => {
                log::info!("DNS TCP server stopping");
                return Ok(());
            }
        };

        match accepted {
            Ok((stream, client_addr)) => {
                let dns_cx = dns_cx.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) =
                        serve_connection(dns_cx, DnsStream::Tcp(stream), client_addr).await
                    {
                        log::error!("Failed to read DNS TCP message from {}: {}", client_addr, e);
                    }
                });
            }
            Err(e) => {
                log::error!("Failed to accept DNS TCP connection: {}", e);
            }
        }
    }
}
