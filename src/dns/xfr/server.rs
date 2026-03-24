use super::{axfr, error::XfrError, ixfr, wire};
use crate::{config, log_info, log_warn};
use domain::base::iana::Rtype;
use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpStream;

pub fn secondary_servers_from_config() -> Vec<IpAddr> {
    let secondary_servers_str = config::get_config::<String>("xfr.secondary_addrs");
    secondary_servers_str
        .split(',')
        .filter_map(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return None;
            }

            match trimmed.parse::<SocketAddr>() {
                Ok(addr) => Some(addr.ip()),
                Err(_) => trimmed.parse::<IpAddr>().ok(),
            }
        })
        .collect()
}

pub fn is_xfr_query_type(qtype: Rtype) -> bool {
    matches!(qtype, Rtype::SOA | Rtype::AXFR | Rtype::IXFR)
}

pub async fn handle_tcp_query(
    stream: &mut TcpStream,
    client_addr: SocketAddr,
    secondary_servers: &[IpAddr],
    query_data: &[u8],
) -> Result<(), XfrError> {
    let client_ip = client_addr.ip();

    validate_secondary_acl(client_ip, secondary_servers)?;

    let (zone_name, qtype, client_serial, query_id) = wire::parse_query(&query_data)?;

    log_info!(
        "XFR TCP query: zone={:?}, qtype={:?}, from={}",
        zone_name.to_string(),
        qtype,
        client_ip
    );

    match qtype {
        Rtype::SOA => {
            axfr::handle_soa(stream, &zone_name, query_id, client_ip).await?;
        }
        Rtype::AXFR => {
            axfr::handle_axfr(stream, &zone_name, query_id, client_ip).await?;
        }
        Rtype::IXFR => {
            ixfr::handle_ixfr(stream, &zone_name, query_id, client_serial, client_ip).await?;
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

pub async fn handle_udp_query(
    client_addr: SocketAddr,
    secondary_servers: &[IpAddr],
    query_data: &[u8],
) -> Result<(), XfrError> {
    let client_ip = client_addr.ip();

    validate_secondary_acl(client_ip, secondary_servers)?;

    let (zone_name, qtype, _client_serial, _query_id) = wire::parse_query(query_data)?;

    if is_xfr_query_type(qtype) {
        log_warn!(
            "XFR-like UDP query is not supported (zone={:?}, qtype={:?}, from={})",
            zone_name.to_string(),
            qtype,
            client_ip
        );

        return Err(XfrError::InvalidQuery(
            "XFR over UDP is not supported".to_string(),
        ));
    }

    Err(XfrError::InvalidQuery(format!(
        "Unsupported query type: {:?}",
        qtype
    )))
}

fn validate_secondary_acl(client_ip: IpAddr, secondary_servers: &[IpAddr]) -> Result<(), XfrError> {
    if !secondary_servers.is_empty() && !secondary_servers.contains(&client_ip) {
        log_warn!(
            "XFR request denied from {} (not a configured secondary server)",
            client_ip
        );
        return Err(XfrError::AccessDenied(format!(
            "IP {} not allowed",
            client_ip
        )));
    }

    Ok(())
}
