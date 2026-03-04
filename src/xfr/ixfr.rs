use super::{axfr, catalog, delta, error::XfrError, wire};
use crate::{database::get_zone_repository, log_info, log_warn};
use domain::base::{Name, iana::Rtype};
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::net::TcpStream;

/// Handle IXFR
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

    let zone_name_str = zone_name.to_string();
    let zone_name_str = zone_name_str.trim_end_matches('.');

    // Check if this is a catalog zone request. Fallback to AXFR
    if catalog::is_catalog_zone(zone_name_str) {
        log_info!("IXFR: Catalog zone requested, falling back to AXFR");
        return axfr::handle_axfr(stream, zone_name, query_id, client_ip).await;
    }

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

    // If client is up-to-date, send single SOA response
    if client_serial == current_serial {
        log_info!("IXFR: Client is up-to-date (serial={})", current_serial);
        return send_up_to_date_response(stream, zone_name, query_id, &zone).await;
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

    // Try to get changes from zone_changes table
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

    send_ixfr_response(stream, zone_name, query_id, &zone, &changes).await?;

    log_info!("IXFR completed for zone {}", zone_name_str);

    Ok(())
}

/// Send response when client is up-to-date (single SOA)
async fn send_up_to_date_response(
    stream: &mut TcpStream,
    zone_name: &Name<Vec<u8>>,
    query_id: u16,
    zone: &crate::database::model::zone::Zone,
) -> Result<(), XfrError> {
    let mut builder = wire::DnsMessageBuilder::new(query_id, zone_name, Rtype::IXFR);

    builder.add_soa(zone, zone.serial as u32)?;

    let message = builder.build();
    wire::write_tcp_message(stream, &message).await?;

    Ok(())
}

/// Send IXFR response with incremental changes
async fn send_ixfr_response(
    stream: &mut TcpStream,
    zone_name: &Name<Vec<u8>>,
    query_id: u16,
    zone: &crate::database::model::zone::Zone,
    changes: &[delta::ZoneChange],
) -> Result<(), XfrError> {
    let mut builder = wire::DnsMessageBuilder::new(query_id, zone_name, Rtype::IXFR);

    // Add initial SOA record
    builder.add_soa(zone, zone.serial as u32)?;

    // Group changes by serial
    let mut changes_by_serial: HashMap<u32, Vec<&delta::ZoneChange>> = HashMap::new();
    for change in changes {
        changes_by_serial
            .entry(change.serial)
            .or_default()
            .push(change);
    }

    // Get sorted serials
    let mut serials: Vec<u32> = changes_by_serial.keys().copied().collect();
    serials.sort();

    // Process each serial in order
    for (idx, &serial) in serials.iter().enumerate() {
        let serial_changes = &changes_by_serial[&serial];

        // Old serial (previous serial or client serial for first change)
        let old_serial = if idx == 0 {
            serial - 1
        } else {
            serials[idx - 1]
        };

        // Add old SOA (deletion section marker)
        builder.add_soa(zone, old_serial)?;

        // Add all DEL operations for this serial
        for change in serial_changes.iter().filter(|c| c.operation == "DEL") {
            add_change_to_builder(&mut builder, change)?;
        }

        // Add new SOA (addition section marker)
        builder.add_soa(zone, serial)?;

        // Add all ADD operations for this serial
        for change in serial_changes.iter().filter(|c| c.operation == "ADD") {
            add_change_to_builder(&mut builder, change)?;
        }
    }

    // Add final SOA record to indicate end of transfer
    builder.add_soa(zone, zone.serial as u32)?;
    let message = builder.build();
    wire::write_tcp_message(stream, &message).await?;

    Ok(())
}

/// Add a zone change record to the message builder
fn add_change_to_builder(
    builder: &mut wire::DnsMessageBuilder,
    change: &delta::ZoneChange,
) -> Result<(), XfrError> {
    let ttl = change.record_ttl.unwrap_or(3600) as u32;

    match change.record_type.as_str() {
        "A" => {
            let addr: std::net::Ipv4Addr = change.record_value.parse().map_err(|_| {
                XfrError::ProtocolError(format!("Invalid A record: {}", change.record_value))
            })?;
            builder.add_a_record(&change.record_name, ttl, addr)?;
        }
        "AAAA" => {
            let addr: std::net::Ipv6Addr = change.record_value.parse().map_err(|_| {
                XfrError::ProtocolError(format!("Invalid AAAA record: {}", change.record_value))
            })?;
            builder.add_aaaa_record(&change.record_name, ttl, addr)?;
        }
        "CNAME" => {
            builder.add_cname_record(&change.record_name, ttl, &change.record_value)?;
        }
        "MX" => {
            let priority = change.record_priority.unwrap_or(10) as u16;
            builder.add_mx_record(&change.record_name, ttl, priority, &change.record_value)?;
        }
        "NS" => {
            builder.add_ns_record(&change.record_name, ttl, &change.record_value)?;
        }
        "TXT" => {
            builder.add_txt_record(&change.record_name, ttl, &change.record_value)?;
        }
        _ => {
            log_info!("Skipping unsupported record type: {}", change.record_type);
        }
    }

    Ok(())
}
