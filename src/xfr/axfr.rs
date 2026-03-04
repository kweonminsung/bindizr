use super::{error::XfrError, wire};
use crate::{
    database::{get_record_repository, get_zone_repository},
    log_info,
};
use domain::base::{iana::Rtype, Name};
use std::net::IpAddr;
use tokio::net::TcpStream;

/// Handle AXFR (Full Zone Transfer) request
pub async fn handle_axfr(
    stream: &mut TcpStream,
    zone_name: &Name<Vec<u8>>,
    query_id: u16,
    client_ip: IpAddr,
) -> Result<(), XfrError> {
    log_info!(
        "AXFR request for zone {:?} from {}",
        zone_name.to_string(),
        client_ip
    );

    // Convert zone name to string
    let zone_name_str = zone_name.to_string();
    let zone_name_str = zone_name_str.trim_end_matches('.');

    // Get zone from database
    let zone_repo = get_zone_repository();
    let zone = zone_repo
        .get_by_name(zone_name_str)
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))?
        .ok_or_else(|| XfrError::ZoneNotFound(zone_name_str.to_string()))?;

    // Get all records for the zone
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

    // Build DNS AXFR response message
    let mut builder = wire::DnsMessageBuilder::new(query_id, zone_name, Rtype::AXFR);

    // AXFR format:
    // 1. SOA record (start marker)
    // 2. All zone records
    // 3. SOA record (end marker)

    // Add SOA at the beginning
    builder.add_soa(&zone, zone.serial as u32)?;

    // Add all records
    for record in &records {
        builder.add_record(record)?;
    }

    // Add SOA at the end (same as beginning)
    builder.add_soa(&zone, zone.serial as u32)?;

    // Build and send message
    let message = builder.build();
    wire::write_tcp_message(stream, &message).await?;

    log_info!(
        "AXFR completed for zone {}: sent {} records + 2 SOA records",
        zone_name_str,
        records.len()
    );

    Ok(())
}
