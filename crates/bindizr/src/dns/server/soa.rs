//! Serves SOA queries over TCP and UDP, used by secondaries to poll the
//! primary's serial.

use std::net::{IpAddr, SocketAddr};

use bindizr_core::{
    config,
    dns::{
        message,
        message::{Rcode, Rtype},
    },
    log_info, log_warn,
};
use bindizr_service::zone::ZoneService;
use tokio::net::{TcpStream, UdpSocket};

use crate::dns::{
    error::XfrError,
    server::{acl::SecondaryAcl, catalog, validate_secondary_acl},
    wire,
};

pub(crate) async fn handle_tcp_soa(
    stream: &mut TcpStream,
    client_addr: SocketAddr,
    secondary_acl: &SecondaryAcl,
    query: &message::ParsedQuery,
) -> Result<(), XfrError> {
    let response = build_soa_response(query, client_addr.ip(), secondary_acl).await?;
    wire::write_tcp_message(stream, &response).await?;
    Ok(())
}

pub(crate) async fn handle_udp_soa(
    socket: &UdpSocket,
    client_addr: SocketAddr,
    secondary_acl: &SecondaryAcl,
    query: &message::ParsedQuery,
) -> Result<(), XfrError> {
    let response = build_soa_response(query, client_addr.ip(), secondary_acl).await?;
    socket.send_to(&response, client_addr).await?;
    Ok(())
}

/// `bindizr doctor` probes over the wire, reaching a concrete `listen_addr` from it.
fn is_self_probe(client_ip: IpAddr) -> bool {
    // A v4 client on a `::` listener arrives mapped, so canonicalize first.
    let client_ip = client_ip.to_canonical();
    client_ip.is_loopback() || client_ip == config::bindizr_config().dns.listen_addr.to_canonical()
}

/// The response bytes, which TCP and UDP send alike.
async fn build_soa_response(
    query: &message::ParsedQuery,
    client_ip: IpAddr,
    secondary_acl: &SecondaryAcl,
) -> Result<Vec<u8>, XfrError> {
    let zone_name_str = query.zone_name.as_str();

    if !is_self_probe(client_ip)
        && validate_secondary_acl(client_ip, secondary_acl)
            .await
            .is_err()
    {
        log_warn!(
            "Refused SOA query for {:?} from {}",
            zone_name_str,
            client_ip
        );
        return Ok(query.error_response(Rcode::REFUSED));
    }

    log_info!("SOA query for zone {:?} from {}", zone_name_str, client_ip);

    let mut builder = message::DnsMessageBuilder::new(query.query_id, &query.qname, Rtype::SOA);

    if catalog::is_catalog_zone(zone_name_str) {
        log_info!("SOA query for catalog zone: {}", catalog::CATALOG_ZONE_NAME);
        let (catalog_zone, _) = catalog::generate_catalog_zone().await?;
        builder.add_catalog_soa(
            &catalog_zone,
            bindizr_core::dns::serial_to_u32(catalog_zone.serial)?,
        )?;
        return Ok(builder.build());
    }

    let Some(zone) = ZoneService::find_by_name(zone_name_str).await? else {
        return Ok(query.error_response(Rcode::NOTAUTH));
    };

    log_info!(
        "SOA response: zone {} serial={}",
        zone_name_str,
        zone.serial
    );

    builder.add_soa(&zone, bindizr_core::dns::serial_to_u32(zone.serial)?)?;

    Ok(builder.build())
}
