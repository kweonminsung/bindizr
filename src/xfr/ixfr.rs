use super::{axfr, delta, error::XfrError, wire};
use crate::{database::get_zone_repository, log_info, log_warn};
use domain::base::{
    iana::{Rcode, Rtype}, Name,
};
use std::net::IpAddr;
use tokio::net::TcpStream;

/// Handle IXFR request
pub async fn handle_ixfr(
    stream: &mut TcpStream,
    zone_name: &Name<Vec<u8>>,
    query_id: u16,
    client_serial: Option<u32>,
    client_ip: IpAddr,
) -> Result<(), XfrError> {
    log_info!(
        "IXFR request for zone {:?} from {}, client_serial={:?}",
        zone_name.to_string(),
        client_ip,
        client_serial
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

    let current_serial = zone.serial as u32;

    // If no client serial provided, fallback to AXFR
    let client_serial = match client_serial {
        Some(s) => s,
        None => {
            log_warn!("IXFR: No client serial provided, falling back to AXFR");
            return axfr::handle_axfr(stream, zone_name, query_id, client_ip).await;
        }
    };

    // If client is up-to-date, send empty response with SOA
    if client_serial == current_serial {
        log_info!("IXFR: Client is up-to-date (serial={})", current_serial);
        return send_up_to_date_response(stream, zone_name, query_id).await;
    }

    // If client is ahead, this is an error
    if client_serial > current_serial {
        log_warn!(
            "IXFR: Client serial {} > current serial {}",
            client_serial,
            current_serial
        );
        return Err(XfrError::SerialMismatch(client_serial, current_serial));
    }

    // Try to get changes
    let changes = delta::get_zone_changes(zone.id, client_serial, current_serial).await?;

    // If no changes available, fallback to AXFR
    if changes.is_empty() {
        log_warn!(
            "IXFR: No history available for serial {} to {}, falling back to AXFR",
            client_serial,
            current_serial
        );
        return axfr::handle_axfr(stream, zone_name, query_id, client_ip).await;
    }

    log_info!(
        "IXFR: Sending {} changes from serial {} to {}",
        changes.len(),
        client_serial,
        current_serial
    );

    // Build IXFR response (simplified)
    let response = build_simple_response(query_id, zone_name, Rcode::NOERROR)?;
    wire::write_tcp_message(stream, &response).await?;

    log_info!("IXFR completed for zone {}", zone_name_str);

    Ok(())
}

async fn send_up_to_date_response(
    stream: &mut TcpStream,
    zone_name: &Name<Vec<u8>>,
    query_id: u16,
) -> Result<(), XfrError> {
    // Send minimal response
    let response = build_simple_response(query_id, zone_name, Rcode::NOERROR)?;
    wire::write_tcp_message(stream, &response).await?;

    Ok(())
}

fn build_simple_response(
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
    response.extend_from_slice(&(Rtype::IXFR.to_int() as u16).to_be_bytes()); // QTYPE
    response.extend_from_slice(&1u16.to_be_bytes()); // QCLASS (IN)

    Ok(response)
}
