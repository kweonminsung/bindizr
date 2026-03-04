use super::{axfr, error::XfrError, ixfr, wire};
use crate::{config, log_error, log_info, log_warn};
use domain::base::iana::Rtype;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use tokio::net::{TcpListener, TcpStream};

pub struct XfrServer {
    listen_addr: SocketAddr,
    allow_transfer: Vec<IpAddr>,
}

impl Default for XfrServer {
    fn default() -> Self {
        Self::new()
    }
}

impl XfrServer {
    pub fn new() -> Self {
        let listen_addr_str = config::get_config::<String>("xfr.listen_addr");
        let listen_port = config::get_config::<u16>("xfr.listen_port");
        let listen_addr = SocketAddr::new(
            IpAddr::from_str(&listen_addr_str).expect("Invalid XFR listen address"),
            listen_port,
        );

        // Load ACL
        let allow_transfer_str = config::get_config::<String>("xfr.allow_transfer");
        let allow_transfer: Vec<IpAddr> = allow_transfer_str
            .split(',')
            .map(|s| s.trim())
            .filter_map(|s| IpAddr::from_str(s).ok())
            .collect();

        Self {
            listen_addr,
            allow_transfer,
        }
    }

    pub async fn start(&self) -> Result<(), XfrError> {
        let listener = TcpListener::bind(self.listen_addr)
            .await
            .map_err(XfrError::IoError)?;

        log_info!("XFR server listening on {}", self.listen_addr);

        loop {
            match listener.accept().await {
                Ok((stream, client_addr)) => {
                    let allow_transfer = self.allow_transfer.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, client_addr, allow_transfer).await
                        {
                            log_error!("XFR connection error from {}: {}", client_addr, e);
                        }
                    });
                }
                Err(e) => {
                    log_error!("Failed to accept connection: {}", e);
                }
            }
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    client_addr: SocketAddr,
    allow_transfer: Vec<IpAddr>,
) -> Result<(), XfrError> {
    let client_ip = client_addr.ip();

    log_info!("XFR connection from {}", client_addr);

    // Check ACL
    if !allow_transfer.is_empty() && !allow_transfer.contains(&client_ip) {
        log_warn!("XFR request denied from {} (not in ACL)", client_ip);
        return Err(XfrError::AccessDenied(format!(
            "IP {} not allowed",
            client_ip
        )));
    }

    // Read DNS query
    let query_data = wire::read_tcp_message(&mut stream).await?;

    // Parse query (returns zone_name, qtype, client_serial, query_id)
    let (zone_name, qtype, client_serial, query_id) = wire::parse_query(&query_data)?;

    log_info!(
        "XFR query: zone={:?}, qtype={:?}, from={}",
        zone_name.to_string(),
        qtype,
        client_ip
    );

    // Dispatch based on query type
    match qtype {
        Rtype::AXFR => {
            axfr::handle_axfr(&mut stream, &zone_name, query_id, client_ip).await?;
        }
        Rtype::IXFR => {
            ixfr::handle_ixfr(&mut stream, &zone_name, query_id, client_serial, client_ip).await?;
        }
        _ => {
            log_warn!("Unsupported query type: {:?}", qtype);
            return Err(XfrError::InvalidQuery(format!(
                "Unsupported query type: {:?}",
                qtype
            )));
        }
    }

    Ok(())
}
