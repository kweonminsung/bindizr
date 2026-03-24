use super::{catalog, error::XfrError, wire};
use crate::{
    database::{get_record_repository, get_zone_repository},
    log_info,
};
use domain::base::{Name, iana::Rtype};
use std::net::IpAddr;
use tokio::net::TcpStream;

/// Handle AXFR
pub async fn handle_axfr(
    stream: &mut TcpStream,
    zone_name: &Name<Vec<u8>>,
    query_id: u16,
    client_ip: IpAddr,
) -> Result<(), XfrError> {
    handle_axfr_with_qtype(stream, zone_name, query_id, client_ip, Rtype::AXFR).await
}

/// Handle AXFR payload with a specific response question type.
/// IXFR fallback should keep QTYPE=IXFR to match the original query.
pub async fn handle_axfr_with_qtype(
    stream: &mut TcpStream,
    zone_name: &Name<Vec<u8>>,
    query_id: u16,
    client_ip: IpAddr,
    response_qtype: Rtype,
) -> Result<(), XfrError> {
    log_info!(
        "AXFR request for zone {:?} from {}",
        zone_name.to_string(),
        client_ip
    );

    let zone_name_owned = zone_name.to_string();
    let zone_name_str = zone_name_owned.trim_end_matches('.');

    // Check if this is a catalog zone request
    if catalog::is_catalog_zone(zone_name_str) {
        return catalog::handle_catalog_axfr_with_qtype(
            stream,
            zone_name,
            query_id,
            response_qtype,
        )
        .await;
    }

    let zone_repo = get_zone_repository();
    let zone = zone_repo
        .get_by_name(zone_name_str)
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))?
        .ok_or_else(|| XfrError::ZoneNotFound(zone_name_str.to_string()))?;

    let record_repo = get_record_repository();
    let records = record_repo
        .get_by_zone_id(zone.id)
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))?;

    log_info!(
        "AXFR: zone {} has {} records, serial={}",
        zone_name_str,
        records.len(),
        zone.serial
    );

    // Build and send AXFR response
    let mut builder = wire::DnsMessageBuilder::new(query_id, zone_name, response_qtype);

    // Add initial SOA record
    builder.add_soa(&zone, zone.serial as u32)?;

    // Add all records
    for record in &records {
        builder.add_record(record, &zone.name)?;
    }

    // Add final SOA record to indicate end of transfer
    builder.add_soa(&zone, zone.serial as u32)?;
    let message = builder.build();
    wire::write_tcp_message(stream, &message).await?;

    log_info!(
        "AXFR completed for zone {}: sent {} records + 2 SOA records",
        zone_name_str,
        records.len()
    );

    Ok(())
}
