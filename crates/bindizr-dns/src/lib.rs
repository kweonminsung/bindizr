//! DNS front end: the authoritative TCP/UDP server plus zone transfer
//! (AXFR/IXFR), NOTIFY, SOA queries, RFC 2136 nsupdate, and secondary ACLs.

pub(crate) mod address;
pub mod client;
pub(crate) mod error;
pub(crate) mod server;
pub mod status;
pub(crate) mod wire;

use std::{io::ErrorKind, net::SocketAddr, time::Duration};

pub(crate) use bindizr_core::{config, log_error, log_info, log_warn, metrics, model};
pub(crate) use bindizr_service as service;
use domain::base::iana::Rtype;
use server::acl::SecondaryAcl;
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Initializes the DNS service: prepares the catalog zone and spawns the TCP and UDP servers.
pub async fn initialize() {
    server::initialize().await;

    let bindizr_config = config::bindizr_config();
    let listen_addr = SocketAddr::new(
        bindizr_config.dns.listen_addr,
        bindizr_config.dns.listen_port,
    );

    let secondary_acl = server::acl::secondary_acl_from_config();
    let tcp_secondary_acl = secondary_acl.clone();

    tokio::spawn(async move {
        if let Err(e) = run_tcp_server(listen_addr, tcp_secondary_acl).await {
            log_error!("DNS TCP server error: {}", e);
        }
    });

    tokio::spawn(async move {
        if let Err(e) = run_udp_server(listen_addr, secondary_acl).await {
            log_error!("DNS UDP server error: {}", e);
        }
    });
}

async fn run_tcp_server(
    listen_addr: SocketAddr,
    secondary_acl: SecondaryAcl,
) -> Result<(), String> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| format!("Failed to bind DNS TCP listener on {}: {}", listen_addr, e))?;

    log_info!("DNS TCP server listening on {}", listen_addr);

    loop {
        match listener.accept().await {
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
        let query_data = match timeout(TCP_IDLE_TIMEOUT, crate::wire::read_tcp_message(&mut stream))
            .await
        {
            Ok(Ok(query_data)) => query_data,
            Ok(Err(crate::error::XfrError::IoError(e))) if e.kind() == ErrorKind::UnexpectedEof => {
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

        handle_tcp_query(&mut stream, client_addr, &secondary_acl, &query_data).await?;
    }

    Ok(())
}

async fn handle_tcp_query(
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

    let query = match wire::ParsedQuery::parse(query_data) {
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
    listen_addr: SocketAddr,
    secondary_acl: SecondaryAcl,
) -> Result<(), String> {
    let socket = UdpSocket::bind(listen_addr)
        .await
        .map_err(|e| format!("Failed to bind DNS UDP socket on {}: {}", listen_addr, e))?;

    log_info!("DNS UDP server listening on {}", listen_addr);

    let mut buf = vec![0u8; 65535];

    loop {
        let (len, client_addr) = match socket.recv_from(&mut buf).await {
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

        let query = match wire::ParsedQuery::parse(query_data) {
            Ok(query) => query,
            Err(_) => continue,
        };

        if query.qtype == Rtype::SOA {
            if let Err(e) = server::soa::handle_udp_soa(&socket, client_addr, &query).await {
                log_warn!("Failed to handle SOA UDP query from {}: {}", client_addr, e);
            }
        } else if server::is_xfr_query_type(query.qtype) {
            if let Err(e) = server::handle_udp_query(client_addr, &secondary_acl, &query).await {
                log_warn!("Failed to handle XFR UDP query from {}: {}", client_addr, e);
            }
        }
    }
}
