pub(crate) mod acl;
pub(crate) mod address;
pub(crate) mod nsupdate;
pub(crate) mod protocol;
pub(crate) mod soa;
pub use bindizr_core::dns::txt;
pub mod xfr;

use std::{io::ErrorKind, net::SocketAddr, time::Duration};

use acl::SecondaryAcl;
pub(crate) use bindizr_core::{config, log_error, log_info, log_warn, model};
pub(crate) use bindizr_service as service;
use domain::base::iana::Rtype;
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

enum QueryRoute {
    Nsupdate,
    Soa,
    Xfr,
    Other(Rtype),
}

pub async fn initialize() {
    xfr::initialize().await;

    let bindizr_config = config::get_bindizr_config();
    let listen_addr = SocketAddr::new(
        bindizr_config.dns.listen_addr,
        bindizr_config.dns.listen_port,
    );

    let secondary_acl = acl::secondary_acl_from_config();
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
        let query_data = match timeout(TCP_IDLE_TIMEOUT, xfr::wire::read_tcp_message(&mut stream))
            .await
        {
            Ok(Ok(query_data)) => query_data,
            Ok(Err(xfr::error::XfrError::IoError(e))) if e.kind() == ErrorKind::UnexpectedEof => {
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
    match classify_query_route(query_data) {
        Ok(QueryRoute::Nsupdate) => {
            nsupdate::handle_tcp_nsupdate(stream, query_data, client_addr).await?;
        }
        Ok(QueryRoute::Soa) => {
            soa::handle_tcp_soa(stream, client_addr, query_data)
                .await
                .map_err(|e| format!("Failed to handle SOA TCP query: {}", e))?;
        }
        Ok(QueryRoute::Xfr) => {
            xfr::handle_tcp_query(stream, client_addr, secondary_acl, query_data)
                .await
                .map_err(|e| format!("Failed to handle XFR TCP query: {}", e))?;
        }
        Ok(QueryRoute::Other(qtype)) => {
            log_info!(
                "Ignoring non-XFR DNS TCP query from {} (qtype={:?})",
                client_addr,
                qtype
            );
        }
        Err(e) => {
            log_warn!("Failed to parse DNS TCP query from {}: {}", client_addr, e);
        }
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

        match classify_query_route(query_data) {
            Ok(QueryRoute::Nsupdate) => {
                if let Err(e) =
                    nsupdate::handle_udp_nsupdate(&socket, query_data, client_addr).await
                {
                    log_error!("NSUPDATE UDP handler failed for {}: {}", client_addr, e);
                }
            }
            Ok(QueryRoute::Soa) => {
                if let Err(e) = soa::handle_udp_soa(&socket, client_addr, query_data).await {
                    log_warn!("Failed to handle SOA UDP query from {}: {}", client_addr, e);
                }
            }
            Ok(QueryRoute::Xfr) => {
                if let Err(e) = xfr::handle_udp_query(client_addr, &secondary_acl, query_data).await
                {
                    log_warn!("Failed to handle XFR UDP query from {}: {}", client_addr, e);
                }
            }
            Ok(QueryRoute::Other(_)) => {}
            Err(_) => {}
        }
    }
}

fn classify_query_route(query_data: &[u8]) -> Result<QueryRoute, String> {
    if nsupdate::is_nsupdate(query_data) {
        return Ok(QueryRoute::Nsupdate);
    }

    let (_, qtype, _, _) = xfr::wire::parse_query(query_data).map_err(|e| e.to_string())?;

    if qtype == Rtype::SOA {
        Ok(QueryRoute::Soa)
    } else if xfr::is_xfr_query_type(qtype) {
        Ok(QueryRoute::Xfr)
    } else {
        Ok(QueryRoute::Other(qtype))
    }
}
