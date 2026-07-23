//! Serves SOA queries over TCP and UDP, used by secondaries to poll the
//! primary's serial.

use std::net::{IpAddr, SocketAddr};

use domain::base::iana::Rtype;
use tokio::net::{TcpStream, UdpSocket};

use crate::{error::XfrError, log_info, server::catalog, service::zone::ZoneService, wire};

pub(crate) async fn handle_tcp_soa(
    stream: &mut TcpStream,
    client_addr: SocketAddr,
    query: &wire::ParsedQuery,
) -> Result<(), XfrError> {
    let response = soa_response_bytes(query, client_addr.ip()).await?;
    wire::write_tcp_message(stream, &response).await?;
    Ok(())
}

pub(crate) async fn handle_udp_soa(
    socket: &UdpSocket,
    client_addr: SocketAddr,
    query: &wire::ParsedQuery,
) -> Result<(), XfrError> {
    let response = soa_response_bytes(query, client_addr.ip()).await?;
    socket.send_to(&response, client_addr).await?;
    Ok(())
}

/// Build the SOA response bytes, mapping an unknown zone to a NOTAUTH response
/// (TCP and UDP send identical bytes).
async fn soa_response_bytes(
    query: &wire::ParsedQuery,
    client_ip: IpAddr,
) -> Result<Vec<u8>, XfrError> {
    match build_soa_response(query, client_ip).await {
        Ok(response) => Ok(response),
        Err(XfrError::ZoneNotFound(_)) => Ok(wire::build_error_response(
            query.query_id,
            &query.qname,
            query.qtype,
            crate::protocol::RCODE_NOTAUTH,
        )),
        Err(err) => Err(err),
    }
}

async fn build_soa_response(
    query: &wire::ParsedQuery,
    client_ip: IpAddr,
) -> Result<Vec<u8>, XfrError> {
    log_info!(
        "SOA query for zone {:?} from {}",
        query.qname.to_string(),
        client_ip
    );

    let zone_name_owned = query.qname.to_string();
    let zone_name_str = zone_name_owned.trim_end_matches('.');

    if catalog::is_catalog_zone(zone_name_str) {
        log_info!("SOA query for catalog zone: {}", catalog::CATALOG_ZONE_NAME);
        let (catalog_zone, _) = catalog::generate_catalog_zone().await?;

        let mut builder = wire::DnsMessageBuilder::new(query.query_id, &query.qname, Rtype::SOA);
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

    let mut builder = wire::DnsMessageBuilder::new(query.query_id, &query.qname, Rtype::SOA);
    builder.add_soa(&zone, zone.serial as u32)?;

    Ok(builder.build())
}
