//! XoT listener, TLS configuration, and connection negotiation.

use std::{future::Future, sync::Arc, time::Duration};

use rustls::ServerConfig;
use tokio::{io::AsyncWriteExt as _, net::TcpListener, sync::Semaphore, time::timeout};
use tokio_rustls::TlsAcceptor;

use super::{connection::serve_connection, error::DnsError, server::DnsContext, stream::DnsStream};
use crate::tls::TlsCertificate;

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

    loop {
        let permit = tokio::select! {
            permit = open.clone().acquire_owned() => permit?,
            () = &mut stop => {
                log::info!("DNS TLS server stopping");
                return Ok(());
            }
        };
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            () = &mut stop => {
                log::info!("DNS TLS server stopping");
                return Ok(());
            }
        };
        match accepted {
            Ok((stream, client_addr)) => {
                let dns_cx = dns_cx.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let mut session =
                        match timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
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
                    if let Err(e) =
                        serve_connection(dns_cx, DnsStream::Tls(Box::new(session)), client_addr)
                            .await
                    {
                        log::error!("Failed to read DNS TLS message from {}: {}", client_addr, e);
                    }
                });
            }
            Err(e) => log::error!("Failed to accept DNS TLS connection: {}", e),
        }
    }
}
