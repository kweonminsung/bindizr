//! XoT listener, TLS configuration, and connection negotiation.

use std::{future::Future, sync::Arc, time::Duration};

use rustls::ServerConfig;
use tokio::{
    io::AsyncWriteExt as _, net::TcpListener, sync::Semaphore, task::JoinSet, time::timeout,
};
use tokio_rustls::TlsAcceptor;

use super::{connection::serve_connection, error::DnsError, server::DnsContext, stream::DnsStream};
use crate::{shutdown::Shutdown, tls::TlsCertificate};

/// Bound the time a silent TLS client holds a connection slot.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Build the server configuration the XoT listener accepts every connection
/// with.
pub(crate) fn build_server_config(certificate: Arc<TlsCertificate>) -> Arc<ServerConfig> {
    // RFC 9103, Section 7.2: XoT uses TLS 1.3 or later and nothing older.
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_cert_resolver(certificate);
    // RFC 9103, Section 7.1: the handshake selects "dot". Other tokens alone
    // fail here; a client naming none is closed by the listener instead.
    config.alpn_protocols = vec![b"dot".to_vec()];
    Arc::new(config)
}

/// Accept DNS TLS connections, completing XoT negotiation before serving queries.
pub(crate) async fn run_tls_server(
    dns_cx: Arc<DnsContext>,
    listener: TcpListener,
    server_config: Arc<ServerConfig>,
    stop: impl Future<Output = ()>,
) -> Result<(), DnsError> {
    // The slot covers the handshake and every query on the session.
    let open = Arc::new(Semaphore::new(
        dns_cx.daemon().config().dns.tcp_max_connections,
    ));
    let acceptor = TlsAcceptor::from(server_config);
    tokio::pin!(stop);
    let connection_shutdown = Shutdown::new();
    let mut connections = JoinSet::new();

    let outcome = loop {
        let permit = tokio::select! {
            biased;
            () = &mut stop => break Ok(()),
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    log::warn!("DNS TLS connection task failed: {}", error);
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
                    log::warn!("DNS TLS connection task failed: {}", error);
                }
                continue;
            }
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((stream, client_addr)) => {
                let dns_cx = dns_cx.clone();
                let acceptor = acceptor.clone();
                let stop = connection_shutdown.waiter();
                connections.spawn(async move {
                    let _permit = permit;
                    tokio::pin!(stop);
                    let handshake = tokio::select! {
                        biased;
                        () = &mut stop => return,
                        result = timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)) => result,
                    };
                    let mut session = match handshake {
                        Ok(Ok(session)) => session,
                        Ok(Err(e)) => {
                            log::warn!("TLS handshake with {} failed: {}", client_addr, e);
                            return;
                        }
                        Err(_) => {
                            log::warn!(
                                "TLS handshake with {} timed out after {:?}",
                                client_addr,
                                TLS_HANDSHAKE_TIMEOUT
                            );
                            return;
                        }
                    };
                    // RFC 9103, Section 7.1: rustls may accept a client without ALPN.
                    if session.get_ref().1.alpn_protocol() != Some(b"dot") {
                        log::warn!(
                            "Closing TLS session with {}: no \"dot\" ALPN was selected",
                            client_addr
                        );
                        if let Err(e) = session.shutdown().await {
                            log::debug!("Closing TLS session with {}: {}", client_addr, e);
                        }
                        return;
                    }
                    if let Err(e) = serve_connection(
                        dns_cx,
                        DnsStream::Tls(Box::new(session)),
                        client_addr,
                        stop,
                    )
                    .await
                    {
                        log::error!("Failed to read DNS TLS message from {}: {}", client_addr, e);
                    }
                });
            }
            Err(e) => log::error!("Failed to accept DNS TLS connection: {}", e),
        }
    };
    drop(listener);
    connection_shutdown.trigger();
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            log::warn!("DNS TLS connection task failed: {}", error);
        }
    }
    log::info!("DNS TLS server stopped");
    outcome
}
