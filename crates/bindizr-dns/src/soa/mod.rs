use std::net::{IpAddr, SocketAddr};

use domain::base::iana::Rtype;
use tokio::net::{TcpStream, UdpSocket};

use crate::{
    log_info,
    service::zone::ZoneService,
    xfr::{catalog, error::XfrError, wire},
};

pub(crate) async fn handle_tcp_soa(
    stream: &mut TcpStream,
    client_addr: SocketAddr,
    _secondary_servers: &[IpAddr],
    query_data: &[u8],
) -> Result<(), XfrError> {
    let client_ip = client_addr.ip();

    let response = match build_soa_response(query_data, client_ip).await {
        Ok(response) => response,
        Err(XfrError::ZoneNotFound(_)) => {
            let (zone_name, qtype, _client_serial, query_id) = wire::parse_query(query_data)?;
            wire::build_error_response(query_id, &zone_name, qtype, wire::RCODE_NOTAUTH)
        }
        Err(err) => return Err(err),
    };
    wire::write_tcp_message(stream, &response).await?;

    Ok(())
}

pub(crate) async fn handle_udp_soa(
    socket: &UdpSocket,
    client_addr: SocketAddr,
    _secondary_servers: &[IpAddr],
    query_data: &[u8],
) -> Result<(), XfrError> {
    let client_ip = client_addr.ip();

    let response = match build_soa_response(query_data, client_ip).await {
        Ok(response) => response,
        Err(XfrError::ZoneNotFound(_)) => {
            let (zone_name, qtype, _client_serial, query_id) = wire::parse_query(query_data)?;
            wire::build_error_response(query_id, &zone_name, qtype, wire::RCODE_NOTAUTH)
        }
        Err(err) => return Err(err),
    };
    socket.send_to(&response, client_addr).await?;

    Ok(())
}

async fn build_soa_response(query_data: &[u8], client_ip: IpAddr) -> Result<Vec<u8>, XfrError> {
    let (zone_name, qtype, _client_serial, query_id) = wire::parse_query(query_data)?;
    if qtype != Rtype::SOA {
        return Err(XfrError::InvalidQuery(format!(
            "Expected SOA query, got {:?}",
            qtype
        )));
    }

    log_info!(
        "SOA query for zone {:?} from {}",
        zone_name.to_string(),
        client_ip
    );

    let zone_name_owned = zone_name.to_string();
    let zone_name_str = zone_name_owned.trim_end_matches('.');

    if catalog::is_catalog_zone(zone_name_str) {
        log_info!("SOA query for catalog zone: {}", catalog::CATALOG_ZONE_NAME);
        let (catalog_zone, _member_zones) = catalog::generate_catalog_zone().await?;

        let mut builder = wire::DnsMessageBuilder::new(query_id, &zone_name, Rtype::SOA);
        builder.add_catalog_soa(&catalog_zone, catalog_zone.serial as u32)?;
        return Ok(builder.build());
    }

    let zone = ZoneService::find(zone_name_str)
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))?
        .ok_or_else(|| XfrError::ZoneNotFound(zone_name_str.to_string()))?;

    log_info!(
        "SOA response: zone {} serial={}",
        zone_name_str,
        zone.serial
    );

    let mut builder = wire::DnsMessageBuilder::new(query_id, &zone_name, Rtype::SOA);
    builder.add_soa(&zone, zone.serial as u32)?;

    log_info!("SOA response sent for zone {}", zone_name_str);

    Ok(builder.build())
}
