pub mod nsupdate;
pub mod soa;
pub mod xfr;

use crate::{config, log_error, log_info, log_warn};
use domain::base::iana::Rtype;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

pub async fn initialize() {
    xfr::initialize().await;

    let listen_addr_str = config::get_config::<String>("listen_addr");
    let listen_port = config::get_config::<u16>("dns.listen_port");
    let listen_addr = SocketAddr::new(
        IpAddr::from_str(&listen_addr_str).expect("Invalid DNS listen address"),
        listen_port,
    );

    let secondary_servers = xfr::server::secondary_servers_from_config();
    let tcp_secondary_servers = secondary_servers.clone();

    tokio::spawn(async move {
        if let Err(e) = run_tcp_server(listen_addr, tcp_secondary_servers).await {
            log_error!("DNS TCP server error: {}", e);
        }
    });

    tokio::spawn(async move {
        if let Err(e) = run_udp_server(listen_addr, secondary_servers).await {
            log_error!("DNS UDP server error: {}", e);
        }
    });
}

async fn run_tcp_server(
    listen_addr: SocketAddr,
    secondary_servers: Vec<IpAddr>,
) -> Result<(), String> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| format!("Failed to bind DNS TCP listener on {}: {}", listen_addr, e))?;

    log_info!("DNS TCP server listening on {}", listen_addr);

    loop {
        match listener.accept().await {
            Ok((stream, client_addr)) => {
                let allowed = secondary_servers.clone();
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
    secondary_servers: Vec<IpAddr>,
) -> Result<(), String> {
    let query_data = xfr::wire::read_tcp_message(&mut stream)
        .await
        .map_err(|e| format!("Failed to read DNS TCP message: {}", e))?;

    if nsupdate::is_nsupdate(&query_data) {
        nsupdate::handle_tcp_nsupdate(&mut stream, &query_data, client_addr).await?;
        return Ok(());
    }

    let (_zone_name, qtype, _client_serial, _query_id) = match xfr::wire::parse_query(&query_data) {
        Ok(parsed) => parsed,
        Err(e) => {
            log_warn!("Failed to parse DNS TCP query from {}: {}", client_addr, e);
            return Ok(());
        }
    };

    if qtype == Rtype::SOA {
        soa::handle_tcp_soa(&mut stream, client_addr, &secondary_servers, &query_data)
            .await
            .map_err(|e| format!("Failed to handle SOA TCP query: {}", e))?;
    } else if xfr::server::is_xfr_query_type(qtype) {
        xfr::server::handle_tcp_query(&mut stream, client_addr, &secondary_servers, &query_data)
            .await
            .map_err(|e| format!("Failed to handle XFR TCP query: {}", e))?;
    } else {
        log_info!(
            "Ignoring non-XFR DNS TCP query from {} (qtype={:?})",
            client_addr,
            qtype
        );
    }

    Ok(())
}

async fn run_udp_server(
    listen_addr: SocketAddr,
    secondary_servers: Vec<IpAddr>,
) -> Result<(), String> {
    let socket = UdpSocket::bind(listen_addr)
        .await
        .map_err(|e| format!("Failed to bind DNS UDP socket on {}: {}", listen_addr, e))?;

    log_info!("DNS UDP server listening on {}", listen_addr);

    let mut buf = [0u8; 65535];

    loop {
        let (len, client_addr) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                log_error!("Failed to receive DNS UDP packet: {}", e);
                continue;
            }
        };

        let query_data = &buf[..len];

        if nsupdate::is_nsupdate(query_data) {
            if let Err(e) = nsupdate::handle_udp_nsupdate(&socket, query_data, client_addr).await {
                log_error!("NSUPDATE UDP handler failed for {}: {}", client_addr, e);
            }
            continue;
        }

        let (_zone_name, qtype, _client_serial, _query_id) =
            match xfr::wire::parse_query(query_data) {
                Ok(parsed) => parsed,
                Err(_) => {
                    continue;
                }
            };

        if qtype == Rtype::SOA {
            if let Err(e) =
                soa::handle_udp_soa(&socket, client_addr, &secondary_servers, query_data).await
            {
                log_warn!("Failed to handle SOA UDP query from {}: {}", client_addr, e);
            }
            continue;
        }

        if xfr::server::is_xfr_query_type(qtype)
            && let Err(e) =
                xfr::server::handle_udp_query(client_addr, &secondary_servers, query_data).await
        {
            log_warn!("Failed to handle XFR UDP query from {}: {}", client_addr, e);
        }
    }
}
