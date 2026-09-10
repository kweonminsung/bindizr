//! DNS front end: the authoritative TCP/UDP server plus zone transfer
//! (AXFR/IXFR), NOTIFY, SOA queries, RFC 2136 nsupdate, and secondary ACLs.

pub(crate) mod error;
pub(crate) mod server;
pub(crate) mod wire;

use std::{future::Future, io::ErrorKind, net::SocketAddr, sync::Arc, time::Duration};

use bindizr_core::{
    config,
    dns::message::{self, Opcode, Rcode, Rtype},
    log_error, log_info, log_warn,
};
use server::acl::SecondaryAcl;
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    time::timeout,
};

use crate::shutdown::Shutdown;

const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Datagrams answered at once; past this the listener drops, since a caller retries.
const MAX_UDP_IN_FLIGHT: usize = 256;

/// Connections served at once; the accept backlog holds the rest.
const MAX_TCP_CONNECTIONS: usize = 128;

/// Initializes the DNS service: prepares the catalog zone and spawns the TCP and UDP servers.
pub(crate) async fn initialize(shutdown: &Shutdown) -> Result<(), String> {
    server::initialize().await;

    let bindizr_config = config::bindizr_config();
    let listen_addr = SocketAddr::new(
        bindizr_config.dns.listen_addr,
        bindizr_config.dns.listen_port,
    );

    let secondary_acl = SecondaryAcl::from_config();
    let tcp_secondary_acl = secondary_acl.clone();

    let tcp_listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| format!("Failed to bind DNS TCP listener on {}: {}", listen_addr, e))?;
    let udp_socket = UdpSocket::bind(listen_addr)
        .await
        .map_err(|e| format!("Failed to bind DNS UDP socket on {}: {}", listen_addr, e))?;

    log_info!("DNS TCP server listening on {}", listen_addr);
    log_info!("DNS UDP server listening on {}", listen_addr);

    let tcp_stop = shutdown.waiter();
    tokio::spawn(async move {
        if let Err(e) = run_tcp_server(tcp_listener, tcp_secondary_acl, tcp_stop).await {
            log_error!("DNS TCP server error: {}", e);
        }
    });

    let udp_stop = shutdown.waiter();
    tokio::spawn(async move {
        if let Err(e) = run_udp_server(udp_socket, secondary_acl, udp_stop).await {
            log_error!("DNS UDP server error: {}", e);
        }
    });

    Ok(())
}

async fn run_tcp_server(
    listener: TcpListener,
    secondary_acl: SecondaryAcl,
    stop: impl Future<Output = ()>,
) -> Result<(), String> {
    let open = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    tokio::pin!(stop);

    loop {
        // The slot comes before the accept, so the backlog holds the excess.
        let permit = tokio::select! {
            permit = open.clone().acquire_owned() => permit.map_err(|e| e.to_string())?,
            () = &mut stop => {
                log_info!("DNS TCP server stopping");
                return Ok(());
            }
        };

        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            () = &mut stop => {
                log_info!("DNS TCP server stopping");
                return Ok(());
            }
        };

        match accepted {
            Ok((stream, client_addr)) => {
                let allowed = secondary_acl.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_tcp_connection(stream, client_addr, allowed).await {
                        log_error!("DNS TCP connection error from {}: {}", client_addr, e);
                    }
                    drop(permit);
                });
            }
            Err(e) => {
                log_error!("Failed to accept DNS TCP connection: {}", e);
            }
        }
    }
}

async fn handle_tcp_connection(
    mut stream: TcpStream,
    client_addr: SocketAddr,
    secondary_acl: SecondaryAcl,
) -> Result<(), String> {
    loop {
        let query_data = match timeout(
            TCP_IDLE_TIMEOUT,
            crate::dns::wire::read_tcp_message(&mut stream),
        )
        .await
        {
            Ok(Ok(query_data)) => query_data,
            Ok(Err(crate::dns::error::XfrError::IoError(e)))
                if e.kind() == ErrorKind::UnexpectedEof =>
            {
                break;
            }
            Ok(Err(e)) => return Err(format!("Failed to read DNS TCP message: {}", e)),
            Err(_) => {
                log_info!(
                    "Closing idle DNS TCP connection from {} after {:?}",
                    client_addr,
                    TCP_IDLE_TIMEOUT
                );
                break;
            }
        };

        dispatch_tcp_query(&mut stream, client_addr, &secondary_acl, &query_data).await?;
    }

    Ok(())
}

async fn dispatch_tcp_query(
    stream: &mut TcpStream,
    client_addr: SocketAddr,
    secondary_acl: &SecondaryAcl,
    query_data: &[u8],
) -> Result<(), String> {
    if message::is_response(query_data) {
        log_warn!("Ignoring a DNS TCP response from {}", client_addr);
        return Ok(());
    }

    // nsupdate owns its own parsing (including TSIG); everything else shares
    // one upfront parse.
    if server::nsupdate::is_nsupdate(query_data) {
        return server::nsupdate::handle_tcp_nsupdate(stream, query_data, client_addr).await;
    }

    let query = match message::ParsedQuery::parse(query_data) {
        Ok(query) => query,
        Err(e) => {
            log_warn!("Failed to parse DNS TCP query from {}: {}", client_addr, e);
            return Ok(());
        }
    };

    if query.opcode != Opcode::QUERY {
        log_info!(
            "Refusing DNS TCP opcode {:?} from {}",
            query.opcode,
            client_addr
        );
        let response = query.error_response(Rcode::NOTIMP);
        return wire::write_tcp_message(stream, &response)
            .await
            .map_err(|e| format!("Failed to answer an unsupported DNS TCP opcode: {}", e));
    }

    if query.qtype == Rtype::SOA {
        server::soa::handle_tcp_soa(stream, client_addr, secondary_acl, &query)
            .await
            .map_err(|e| format!("Failed to handle SOA TCP query: {}", e))?;
    } else if server::is_xfr_query_type(query.qtype) {
        server::handle_tcp_query(stream, client_addr, secondary_acl, &query)
            .await
            .map_err(|e| format!("Failed to handle XFR TCP query: {}", e))?;
    } else {
        // bindizr answers secondaries, not resolvers.
        log_info!(
            "Refusing out-of-scope DNS TCP query from {} (qtype={:?})",
            client_addr,
            query.qtype
        );
        let response = query.error_response(Rcode::REFUSED);
        wire::write_tcp_message(stream, &response)
            .await
            .map_err(|e| format!("Failed to refuse a DNS TCP query: {}", e))?;
    }

    Ok(())
}

async fn run_udp_server(
    socket: UdpSocket,
    secondary_acl: SecondaryAcl,
    stop: impl Future<Output = ()>,
) -> Result<(), String> {
    let socket = Arc::new(socket);
    let in_flight = Arc::new(Semaphore::new(MAX_UDP_IN_FLIGHT));
    let mut buf = vec![0u8; 65535];
    tokio::pin!(stop);

    loop {
        let received = tokio::select! {
            received = socket.recv_from(&mut buf) => received,
            () = &mut stop => {
                log_info!("DNS UDP server stopping");
                return Ok(());
            }
        };

        let (len, client_addr) = match received {
            Ok(v) => v,
            Err(e) => {
                log_error!("Failed to receive DNS UDP packet: {}", e);
                continue;
            }
        };

        let Ok(permit) = in_flight.clone().try_acquire_owned() else {
            log_warn!(
                "Dropping DNS UDP query from {}: {} already in flight",
                client_addr,
                MAX_UDP_IN_FLIGHT
            );
            continue;
        };

        let query_data = buf[..len].to_vec();
        let socket = socket.clone();
        let secondary_acl = secondary_acl.clone();
        tokio::spawn(async move {
            dispatch_udp_query(&socket, client_addr, &secondary_acl, &query_data).await;
            drop(permit);
        });
    }
}

async fn dispatch_udp_query(
    socket: &UdpSocket,
    client_addr: SocketAddr,
    secondary_acl: &SecondaryAcl,
    query_data: &[u8],
) {
    if message::is_response(query_data) {
        log_warn!("Ignoring a DNS UDP response from {}", client_addr);
        return;
    }

    if server::nsupdate::is_nsupdate(query_data) {
        if let Err(e) = server::nsupdate::handle_udp_nsupdate(socket, query_data, client_addr).await
        {
            log_error!("NSUPDATE UDP handler failed for {}: {}", client_addr, e);
        }
        return;
    }

    let Ok(query) = message::ParsedQuery::parse(query_data) else {
        return;
    };

    if query.opcode != Opcode::QUERY {
        log_info!(
            "Refusing DNS UDP opcode {:?} from {}",
            query.opcode,
            client_addr
        );
        send_udp_response(socket, client_addr, &query.error_response(Rcode::NOTIMP)).await;
        return;
    }

    if query.qtype == Rtype::SOA {
        if let Err(e) =
            server::soa::handle_udp_soa(socket, client_addr, secondary_acl, &query).await
        {
            log_warn!("Failed to handle SOA UDP query from {}: {}", client_addr, e);
        }
        return;
    }

    let response = if server::is_xfr_query_type(query.qtype) {
        server::handle_udp_query(client_addr, secondary_acl, &query).await
    } else {
        log_info!(
            "Refusing out-of-scope DNS UDP query from {} (qtype={:?})",
            client_addr,
            query.qtype
        );
        query.error_response(Rcode::REFUSED)
    };
    send_udp_response(socket, client_addr, &response).await;
}

async fn send_udp_response(socket: &UdpSocket, client_addr: SocketAddr, response: &[u8]) {
    if let Err(e) = socket.send_to(response, client_addr).await {
        log_warn!("Failed to answer DNS UDP query from {}: {}", client_addr, e);
    }
}
