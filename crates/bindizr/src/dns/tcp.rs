//! The TCP listener, plain or under TLS: accept, the handshake the listener
//! requires, and the dispatch of each framed query to its handler.

use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};

use bindizr_core::dns::message::{self, ExtendedErrorCode, Opcode, Rcode, Rtype};
use rustls::ServerConfig;
use thiserror::Error;
use tokio::{
    io::AsyncWriteExt as _,
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

use super::{
    error::XfrError,
    server::{self, DnsContext},
    stream::DnsStream,
    wire,
};

const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// A client that connects and says nothing must not hold a connection slot.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Connections served at once; the accept backlog holds the rest.
const MAX_TCP_CONNECTIONS: usize = 128;

/// What a listener does with an accepted socket before serving it: nothing,
/// or a TLS handshake under the XoT server configuration.
#[derive(Debug, Clone)]
pub(crate) enum Handshake {
    None,
    Tls(Arc<ServerConfig>),
}

/// Why a connection was not served, for the listener's log.
#[derive(Debug, Error)]
pub(crate) enum ServeDnsError {
    #[error(transparent)]
    Closed(#[from] tokio::sync::AcquireError),
    #[error("failed to read DNS TCP message: {0}")]
    Read(#[source] XfrError),
    #[error("failed to answer an unsupported DNS TCP opcode: {0}")]
    AnswerOpcode(#[source] XfrError),
    #[error("failed to handle SOA TCP query: {0}")]
    Soa(#[source] XfrError),
    #[error("failed to handle XFR TCP query: {0}")]
    Xfr(#[source] XfrError),
    #[error("failed to refuse a DNS TCP query: {0}")]
    Refusal(#[source] XfrError),
    #[error(transparent)]
    Nsupdate(#[from] server::nsupdate::NsupdateError),
}

/// Accept DNS TCP connections until shutdown, serving each after the
/// handshake its listener requires.
pub(crate) async fn run_tcp_server(
    dns_cx: Arc<DnsContext>,
    listener: TcpListener,
    handshake: Handshake,
    stop: impl Future<Output = ()>,
) -> Result<(), ServeDnsError> {
    let open = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
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
                let handshake = handshake.clone();
                tokio::spawn(async move {
                    serve_connection(&dns_cx, &handshake, stream, client_addr).await;
                    drop(permit);
                });
            }
            Err(e) => {
                log::error!("Failed to accept DNS TCP connection: {}", e);
            }
        }
    }
}

/// Run the handshake the listener requires, then serve the connection. A
/// handshake the client fails is noted, not reported as a server error.
async fn serve_connection(
    dns_cx: &DnsContext,
    handshake: &Handshake,
    stream: TcpStream,
    client_addr: SocketAddr,
) {
    let stream = match handshake {
        Handshake::None => DnsStream::Tcp(stream),
        Handshake::Tls(server_config) => {
            let accept = TlsAcceptor::from(server_config.clone()).accept(stream);
            match timeout(TLS_HANDSHAKE_TIMEOUT, accept).await {
                // RFC 9103, Section 7.1: the handshake selects "dot". rustls
                // completes one that named nothing, so that session is closed here.
                Ok(Ok(mut session)) => {
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
                    DnsStream::Tls(Box::new(session))
                }
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
            }
        }
    };
    if let Err(e) = handle_tcp_connection(dns_cx, stream, client_addr).await {
        log::error!("DNS TCP connection error from {}: {}", client_addr, e);
    }
}

/// Read and dispatch DNS queries on one connection until the client is done
/// or idle.
async fn handle_tcp_connection(
    dns_cx: &DnsContext,
    mut stream: DnsStream,
    client_addr: SocketAddr,
) -> Result<(), ServeDnsError> {
    loop {
        let query_data = match timeout(TCP_IDLE_TIMEOUT, wire::read_tcp_message(&mut stream)).await
        {
            Ok(Ok(query_data)) => query_data,
            Ok(Err(XfrError::Closed)) => break,
            Ok(Err(e)) => return Err(ServeDnsError::Read(e)),
            Err(_) => {
                log::info!(
                    "Closing idle DNS TCP connection from {} after {:?}",
                    client_addr,
                    TCP_IDLE_TIMEOUT
                );
                break;
            }
        };

        dispatch_tcp_query(dns_cx, &mut stream, client_addr, &query_data).await?;
    }

    // A TLS peer is owed close_notify ahead of the FIN; a plain socket closes.
    if let Err(e) = stream.shutdown().await {
        log::debug!("Closing DNS TCP connection from {}: {}", client_addr, e);
    }
    Ok(())
}

/// Route a TCP DNS query to its transfer, update, or SOA handler.
async fn dispatch_tcp_query(
    dns_cx: &DnsContext,
    stream: &mut DnsStream,
    client_addr: SocketAddr,
    query_data: &[u8],
) -> Result<(), ServeDnsError> {
    if message::is_response(query_data) {
        log::warn!("Ignoring a DNS TCP response from {}", client_addr);
        return Ok(());
    }

    // nsupdate owns its own parsing (including TSIG); everything else shares
    // one upfront parse.
    if server::nsupdate::is_nsupdate(query_data) {
        return Ok(
            server::nsupdate::handle_tcp_nsupdate(dns_cx, stream, query_data, client_addr).await?,
        );
    }

    let query = match message::ParsedQuery::parse(query_data) {
        Ok(query) => query,
        Err(e) => {
            log::warn!("Failed to parse DNS TCP query from {}: {}", client_addr, e);
            return Ok(());
        }
    };

    if let Some(response) = query.edns_error_response() {
        log::info!("Refusing the EDNS of a DNS TCP query from {}", client_addr);
        return wire::write_tcp_message(stream, &response)
            .await
            .map_err(ServeDnsError::Refusal);
    }

    if query.opcode != Opcode::QUERY {
        log::info!(
            "Refusing DNS TCP opcode {:?} from {}",
            query.opcode,
            client_addr
        );
        let response = query.error_response(Rcode::NOTIMP, Some(ExtendedErrorCode::NOT_SUPPORTED));
        return wire::write_tcp_message(stream, &response)
            .await
            .map_err(ServeDnsError::AnswerOpcode);
    }

    if query.qtype == Rtype::SOA {
        server::soa::handle_tcp_soa(dns_cx, stream, client_addr, &query, query_data)
            .await
            .map_err(ServeDnsError::Soa)?;
    } else if server::is_xfr_query_type(query.qtype) {
        server::handle_tcp_xfr(dns_cx, stream, client_addr, &query, query_data)
            .await
            .map_err(ServeDnsError::Xfr)?;
    } else {
        // bindizr answers secondaries, not resolvers; over TLS the refusal
        // names its reason (RFC 9103, Section 7.8).
        log::info!(
            "Refusing out-of-scope DNS TCP query from {} (qtype={:?})",
            client_addr,
            query.qtype
        );
        let response = query.error_response(Rcode::REFUSED, Some(ExtendedErrorCode::NOT_SUPPORTED));
        wire::write_tcp_message(stream, &response)
            .await
            .map_err(ServeDnsError::Refusal)?;
    }

    Ok(())
}
