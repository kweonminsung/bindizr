//! DNS front end: the authoritative TCP/UDP server plus zone transfer
//! (AXFR/IXFR), NOTIFY, SOA queries, RFC 2136 nsupdate, and secondary ACLs.

pub(crate) mod error;
pub(crate) mod server;
pub(crate) mod wire;

use std::{future::Future, io::ErrorKind, net::SocketAddr, sync::Arc, time::Duration};

use bindizr_core::dns::message::{self, Opcode, Rcode, Rtype};
use bindizr_service::Context;
use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    task::JoinHandle,
    time::timeout,
};

use self::server::DnsContext;
use crate::{dns::error::XfrError, shutdown::Shutdown};

const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Datagrams answered at once; past this the listener drops, since a caller retries.
const MAX_UDP_IN_FLIGHT: usize = 256;

/// Connections served at once; the accept backlog holds the rest.
const MAX_TCP_CONNECTIONS: usize = 128;

/// Why a DNS listener could not come up.
#[derive(Debug, Error)]
pub(crate) enum StartDnsError {
    /// Names the usual cause when the port is already taken.
    #[error("failed to bind DNS {socket} on {addr}: {source}{}", if source.kind() == std::io::ErrorKind::AddrInUse { " (BIND on this host? change dns.listen_port)" } else { "" })]
    Bind {
        socket: &'static str,
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

/// Why a connection or datagram was not served, for the listener's log.
#[derive(Debug, Error)]
enum ServeDnsError {
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

/// Bring the DNS front end up: prepare the catalog zone and spawn the TCP and
/// UDP servers, handing back their accept loops so the daemon notices one
/// that stops.
pub(crate) async fn initialize(
    cx: Arc<Context>,
    shutdown: &Shutdown,
) -> Result<(JoinHandle<()>, JoinHandle<()>), StartDnsError> {
    let dns_cx = Arc::new(DnsContext::new(cx.clone()));

    // The catalog zone must exist before a secondary asks for it.
    match server::catalog::generate_catalog_zone(&dns_cx).await {
        Ok((catalog, _)) => {
            log::info!(
                "Catalog zone '{}' is ready (serial: {})",
                cx.config().dns.catalog_zone_name,
                catalog.serial
            );
        }
        Err(e) => {
            log::warn!("Failed to generate catalog zone: {}", e);
        }
    }

    let config = cx.config();
    let listen_addr = SocketAddr::new(config.dns.listen_addr, config.dns.listen_port);

    let tcp_listener =
        TcpListener::bind(listen_addr)
            .await
            .map_err(|source| StartDnsError::Bind {
                socket: "TCP listener",
                addr: listen_addr,
                source,
            })?;
    let udp_socket = UdpSocket::bind(listen_addr)
        .await
        .map_err(|source| StartDnsError::Bind {
            socket: "UDP socket",
            addr: listen_addr,
            source,
        })?;

    log::info!("DNS TCP server listening on {}", listen_addr);
    log::info!("DNS UDP server listening on {}", listen_addr);

    let tcp_stop = shutdown.waiter();
    let tcp_cx = dns_cx.clone();
    let tcp_task = tokio::spawn(async move {
        if let Err(e) = run_tcp_server(tcp_cx, tcp_listener, tcp_stop).await {
            log::error!("DNS TCP server error: {}", e);
        }
    });

    let udp_stop = shutdown.waiter();
    let udp_cx = dns_cx;
    let udp_task = tokio::spawn(async move {
        if let Err(e) = run_udp_server(udp_cx, udp_socket, udp_stop).await {
            log::error!("DNS UDP server error: {}", e);
        }
    });

    Ok((tcp_task, udp_task))
}

/// Accept DNS TCP connections until shutdown.
async fn run_tcp_server(
    dns_cx: Arc<DnsContext>,
    listener: TcpListener,
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
                tokio::spawn(async move {
                    if let Err(e) = handle_tcp_connection(&dns_cx, stream, client_addr).await {
                        log::error!("DNS TCP connection error from {}: {}", client_addr, e);
                    }
                    drop(permit);
                });
            }
            Err(e) => {
                log::error!("Failed to accept DNS TCP connection: {}", e);
            }
        }
    }
}

/// Read and dispatch DNS queries on one TCP connection.
async fn handle_tcp_connection(
    dns_cx: &DnsContext,
    mut stream: TcpStream,
    client_addr: SocketAddr,
) -> Result<(), ServeDnsError> {
    loop {
        let query_data = match timeout(
            TCP_IDLE_TIMEOUT,
            crate::dns::wire::read_tcp_message(&mut stream),
        )
        .await
        {
            Ok(Ok(query_data)) => query_data,
            Ok(Err(XfrError::Io(e))) if e.kind() == ErrorKind::UnexpectedEof => {
                break;
            }
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

    Ok(())
}

/// Route a TCP DNS query to its transfer, update, or SOA handler.
async fn dispatch_tcp_query(
    dns_cx: &DnsContext,
    stream: &mut TcpStream,
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

    if query.opcode != Opcode::QUERY {
        log::info!(
            "Refusing DNS TCP opcode {:?} from {}",
            query.opcode,
            client_addr
        );
        let response = query.error_response(Rcode::NOTIMP);
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
        // bindizr answers secondaries, not resolvers.
        log::info!(
            "Refusing out-of-scope DNS TCP query from {} (qtype={:?})",
            client_addr,
            query.qtype
        );
        let response = query.error_response(Rcode::REFUSED);
        wire::write_tcp_message(stream, &response)
            .await
            .map_err(ServeDnsError::Refusal)?;
    }

    Ok(())
}

/// Receive and dispatch DNS UDP datagrams until shutdown.
async fn run_udp_server(
    dns_cx: Arc<DnsContext>,
    socket: UdpSocket,
    stop: impl Future<Output = ()>,
) -> Result<(), ServeDnsError> {
    let socket = Arc::new(socket);
    let in_flight = Arc::new(Semaphore::new(MAX_UDP_IN_FLIGHT));
    let mut buf = vec![0u8; 65535];
    tokio::pin!(stop);

    loop {
        let received = tokio::select! {
            received = socket.recv_from(&mut buf) => received,
            () = &mut stop => {
                log::info!("DNS UDP server stopping");
                return Ok(());
            }
        };

        let (len, client_addr) = match received {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to receive DNS UDP packet: {}", e);
                continue;
            }
        };

        // Drop excess datagrams instead of queuing work; each handler holds its
        // permit until dispatch finishes.
        let Ok(permit) = in_flight.clone().try_acquire_owned() else {
            log::warn!(
                "Dropping DNS UDP query from {}: {} already in flight",
                client_addr,
                MAX_UDP_IN_FLIGHT
            );
            continue;
        };

        let query_data = buf[..len].to_vec();
        let socket = socket.clone();
        let dns_cx = dns_cx.clone();
        tokio::spawn(async move {
            dispatch_udp_query(&dns_cx, &socket, client_addr, &query_data).await;
            drop(permit);
        });
    }
}

/// Dispatch UDP UPDATE, SOA, and XFR queries, refusing unsupported query types.
async fn dispatch_udp_query(
    dns_cx: &DnsContext,
    socket: &UdpSocket,
    client_addr: SocketAddr,
    query_data: &[u8],
) {
    if message::is_response(query_data) {
        log::warn!("Ignoring a DNS UDP response from {}", client_addr);
        return;
    }

    if server::nsupdate::is_nsupdate(query_data) {
        if let Err(e) =
            server::nsupdate::handle_udp_nsupdate(dns_cx, socket, query_data, client_addr).await
        {
            log::error!("NSUPDATE UDP handler failed for {}: {}", client_addr, e);
        }
        return;
    }

    let Ok(query) = message::ParsedQuery::parse(query_data) else {
        return;
    };

    if query.opcode != Opcode::QUERY {
        log::info!(
            "Refusing DNS UDP opcode {:?} from {}",
            query.opcode,
            client_addr
        );
        send_udp_response(socket, client_addr, &query.error_response(Rcode::NOTIMP)).await;
        return;
    }

    if query.qtype == Rtype::SOA {
        if let Err(e) =
            server::soa::handle_udp_soa(dns_cx, socket, client_addr, &query, query_data).await
        {
            log::warn!("Failed to handle SOA UDP query from {}: {}", client_addr, e);
        }
        return;
    }

    let response = if server::is_xfr_query_type(query.qtype) {
        server::handle_udp_xfr(dns_cx, client_addr, &query, query_data).await
    } else {
        log::info!(
            "Refusing out-of-scope DNS UDP query from {} (qtype={:?})",
            client_addr,
            query.qtype
        );
        query.error_response(Rcode::REFUSED)
    };
    send_udp_response(socket, client_addr, &response).await;
}

/// Send a DNS response datagram to the requesting peer.
async fn send_udp_response(socket: &UdpSocket, client_addr: SocketAddr, response: &[u8]) {
    if let Err(e) = socket.send_to(response, client_addr).await {
        log::warn!("Failed to answer DNS UDP query from {}: {}", client_addr, e);
    }
}
