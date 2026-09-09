//! DNS front end: the authoritative TCP/UDP server plus zone transfer
//! (AXFR/IXFR), NOTIFY, SOA queries, RFC 2136 nsupdate, and secondary ACLs.

pub(crate) mod error;
pub(crate) mod server;
pub(crate) mod wire;

use std::{future::Future, io::ErrorKind, net::SocketAddr, time::Duration};

use bindizr_core::{
    config,
    dns::message::{self, Rtype},
    log_error, log_info, log_warn,
};
use server::acl::SecondaryAcl;
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

use crate::shutdown::Shutdown;

const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

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
    tokio::pin!(stop);

    loop {
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

    if query.qtype == Rtype::SOA {
        server::soa::handle_tcp_soa(stream, client_addr, &query)
            .await
            .map_err(|e| format!("Failed to handle SOA TCP query: {}", e))?;
    } else if server::is_xfr_query_type(query.qtype) {
        server::handle_tcp_query(stream, client_addr, secondary_acl, &query)
            .await
            .map_err(|e| format!("Failed to handle XFR TCP query: {}", e))?;
    } else {
        log_info!(
            "Ignoring non-XFR DNS TCP query from {} (qtype={:?})",
            client_addr,
            query.qtype
        );
    }

    Ok(())
}

async fn run_udp_server(
    socket: UdpSocket,
    secondary_acl: SecondaryAcl,
    stop: impl Future<Output = ()>,
) -> Result<(), String> {
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

        let query_data = &buf[..len];

        if server::nsupdate::is_nsupdate(query_data) {
            if let Err(e) =
                server::nsupdate::handle_udp_nsupdate(&socket, query_data, client_addr).await
            {
                log_error!("NSUPDATE UDP handler failed for {}: {}", client_addr, e);
            }
            continue;
        }

        let query = match message::ParsedQuery::parse(query_data) {
            Ok(query) => query,
            Err(_) => continue,
        };

        if query.qtype == Rtype::SOA {
            if let Err(e) = server::soa::handle_udp_soa(&socket, client_addr, &query).await {
                log_warn!("Failed to handle SOA UDP query from {}: {}", client_addr, e);
            }
        } else if server::is_xfr_query_type(query.qtype) {
            match server::handle_udp_query(client_addr, &secondary_acl, &query).await {
                Ok(response) => {
                    if let Err(e) = socket.send_to(&response, client_addr).await {
                        log_warn!("Failed to answer XFR UDP query from {}: {}", client_addr, e);
                    }
                }
                Err(e) => log_warn!("Refused XFR UDP query from {}: {}", client_addr, e),
            }
        }
    }
}
