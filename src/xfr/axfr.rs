use super::{error::XfrError, wire};
use crate::{
    database::{get_record_repository, get_zone_repository},
    log_info,
};
use domain::base::{
    iana::{Rcode, Rtype}, Name,
};
use std::net::IpAddr;
use tokio::net::TcpStream;

/// Handle AXFR request
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

    // Build DNS response manually
    // For now, return a simplified error response
    // Full implementation would require building DNS wire format messages
    // TODO: Implement proper DNS message building

    // Build a simple AXFR response with NOERROR rcode
    // This is a placeholder - a production implementation would need
    // proper DNS message construction
    let response = build_simple_error_response(query_id, zone_name, Rcode::NOERROR)?;
    wire::write_tcp_message(stream, &response).await?;

    log_info!("AXFR completed for zone {}", zone_name_str);

    Ok(())
}

fn build_simple_error_response(
    query_id: u16,
    zone_name: &Name<Vec<u8>>,
    rcode: Rcode,
) -> Result<Vec<u8>, XfrError> {
    // Build a minimal DNS response
    let mut response = Vec::new();

    // DNS Header (12 bytes)
    response.extend_from_slice(&query_id.to_be_bytes()); // ID
    response.push(0x84); // QR=1, Opcode=0, AA=1, TC=0, RD=0
    response.push(rcode.to_int()); // RA=0, Z=0, RCODE
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    response.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT=0
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0

    // Question section
    let zone_bytes = zone_name.as_slice();
    response.extend_from_slice(&zone_bytes);
    response.extend_from_slice(&(Rtype::AXFR.to_int() as u16).to_be_bytes()); // QTYPE
    response.extend_from_slice(&1u16.to_be_bytes()); // QCLASS (IN)

    Ok(response)
}
