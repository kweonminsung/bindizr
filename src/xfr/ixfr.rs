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
        return axfr::handle_axfr_with_qtype(stream, zone_name, query_id, client_ip, Rtype::IXFR)
            .await;
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
            return axfr::handle_axfr_with_qtype(
                stream,
                zone_name,
                query_id,
                client_ip,
                Rtype::IXFR,
            )
            .await;
        }
    };

    // If client is up-to-date, send single SOA response
    if client_serial == current_serial {
        log_info!("IXFR: Client is up-to-date (serial={})", current_serial);
        let current_soa = match delta::get_zone_snapshot(zone.id, current_serial).await? {
            Some(snapshot) => snapshot,
            None => {
                log_warn!("IXFR: Missing SOA snapshot, falling back to AXFR");
                return axfr::handle_axfr_with_qtype(
                    stream,
                    zone_name,
                    query_id,
                    client_ip,
                    Rtype::IXFR,
                )
                .await;
            }
        };
        return send_up_to_date_response(stream, zone_name, query_id, &current_soa).await;
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
        return axfr::handle_axfr_with_qtype(stream, zone_name, query_id, client_ip, Rtype::IXFR)
            .await;
    }

    // Group changes by serial to validate monotonic serial progression
    let mut serials_in_changes: Vec<u32> = changes.iter().map(|c| c.serial).collect();
    serials_in_changes.sort_unstable();
    serials_in_changes.dedup();

    let mut previous_serial = client_serial;
    for &serial in &serials_in_changes {
        if serial <= previous_serial {
            log_warn!(
                "IXFR: Non-monotonic serial chain (previous {}, got {}), falling back to AXFR",
                previous_serial,
                serial
            );
            return axfr::handle_axfr_with_qtype(
                stream,
                zone_name,
                query_id,
                client_ip,
                Rtype::IXFR,
            )
            .await;
        }
        previous_serial = serial;
    }

    // Verify the last serial in changes matches current serial
    if let Some(&last_serial) = serials_in_changes.last()
        && last_serial != current_serial
    {
        log_warn!(
            "IXFR: Last change serial {} != current serial {}, falling back to AXFR",
            last_serial,
            current_serial
        );
        return axfr::handle_axfr_with_qtype(stream, zone_name, query_id, client_ip, Rtype::IXFR)
            .await;
    }

    let mut snapshots_by_serial: HashMap<u32, delta::ZoneSnapshot> = HashMap::new();
    snapshots_by_serial.reserve(serials_in_changes.len() + 1);

    let mut required_snapshot_serials = serials_in_changes.clone();
    required_snapshot_serials.push(client_serial);
    required_snapshot_serials.sort_unstable();
    required_snapshot_serials.dedup();

    for serial in required_snapshot_serials {
        match delta::get_zone_snapshot(zone.id, serial).await? {
            Some(snapshot) => {
                snapshots_by_serial.insert(serial, snapshot);
            }
            None => {
                log_warn!("IXFR: Missing SOA snapshot, falling back to AXFR");
                return axfr::handle_axfr_with_qtype(
                    stream,
                    zone_name,
                    query_id,
                    client_ip,
                    Rtype::IXFR,
                )
                .await;
            }
        }
    }

    // Validate snapshot chain to ensure old/new SOA can be formed for each serial delta.
    for (idx, &serial) in serials_in_changes.iter().enumerate() {
        let old_serial = if idx == 0 {
            client_serial
        } else {
            serials_in_changes[idx - 1]
        };

        if !snapshots_by_serial.contains_key(&old_serial)
            || !snapshots_by_serial.contains_key(&serial)
        {
            log_warn!("IXFR: Missing SOA snapshot, falling back to AXFR");
            return axfr::handle_axfr_with_qtype(
                stream,
                zone_name,
                query_id,
                client_ip,
                Rtype::IXFR,
            )
            .await;
        }
    }

    if !snapshots_by_serial.contains_key(&current_serial) {
        log_warn!("IXFR: Missing SOA snapshot, falling back to AXFR");
        return axfr::handle_axfr_with_qtype(stream, zone_name, query_id, client_ip, Rtype::IXFR)
            .await;
    }

    log_info!(
        "IXFR: Sending {} changes across {} serial steps from {} to {}",
        changes.len(),
        serials_in_changes.len(),
        client_serial,
        current_serial
    );

    send_ixfr_response(
        stream,
        zone_name,
        query_id,
        &zone,
        client_serial,
        &changes,
        &snapshots_by_serial,
    )
    .await?;

    log_info!("IXFR completed for zone {}", zone_name_str);

    Ok(())
}

/// Send response when client is up-to-date (single SOA)
async fn send_up_to_date_response(
    stream: &mut TcpStream,
    zone_name: &Name<Vec<u8>>,
    query_id: u16,
    current_soa: &delta::ZoneSnapshot,
) -> Result<(), XfrError> {
    let mut builder = wire::DnsMessageBuilder::new(query_id, zone_name, Rtype::IXFR);

    builder.add_soa_from_snapshot(current_soa)?;

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
    client_serial: u32,
    changes: &[delta::ZoneChange],
    snapshots_by_serial: &HashMap<u32, delta::ZoneSnapshot>,
) -> Result<(), XfrError> {
    let mut builder = wire::DnsMessageBuilder::new(query_id, zone_name, Rtype::IXFR);

    // Add initial SOA record
    let current_snapshot = snapshots_by_serial
        .get(&(zone.serial as u32))
        .ok_or_else(|| {
            XfrError::ProtocolError("Missing current serial SOA snapshot for IXFR".to_string())
        })?;
    builder.add_soa_from_snapshot(current_snapshot)?;

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
            client_serial
        } else {
            serials[idx - 1]
        };

        // Add old SOA (deletion section marker)
        let old_soa = snapshots_by_serial.get(&old_serial).ok_or_else(|| {
            XfrError::ProtocolError(format!(
                "Missing old SOA snapshot for serial {}",
                old_serial
            ))
        })?;
        builder.add_soa_from_snapshot(old_soa)?;

        // Add all DEL operations for this serial
        for change in serial_changes.iter().filter(|c| c.operation == "DEL") {
            add_change_to_builder(&mut builder, change, &zone.name)?;
        }

        // Add new SOA (addition section marker)
        let new_soa = snapshots_by_serial.get(&serial).ok_or_else(|| {
            XfrError::ProtocolError(format!("Missing new SOA snapshot for serial {}", serial))
        })?;
        builder.add_soa_from_snapshot(new_soa)?;

        // Add all ADD operations for this serial
        for change in serial_changes.iter().filter(|c| c.operation == "ADD") {
            add_change_to_builder(&mut builder, change, &zone.name)?;
        }
    }

    // Add final SOA record to indicate end of transfer
    builder.add_soa_from_snapshot(current_snapshot)?;
    let message = builder.build();
    wire::write_tcp_message(stream, &message).await?;

    Ok(())
}

/// Add a zone change record to the message builder
fn add_change_to_builder(
    builder: &mut wire::DnsMessageBuilder,
    change: &delta::ZoneChange,
    zone_name: &str,
) -> Result<(), XfrError> {
    let ttl = change.record_ttl.unwrap_or(3600) as u32;
    let owner_name = normalize_change_name(&change.record_name, zone_name);

    match change.record_type.as_str() {
        "A" => {
            let addr: std::net::Ipv4Addr = change.record_value.parse().map_err(|_| {
                XfrError::ProtocolError(format!("Invalid A record: {}", change.record_value))
            })?;
            builder.add_a_record(&owner_name, ttl, addr)?;
        }
        "AAAA" => {
            let addr: std::net::Ipv6Addr = change.record_value.parse().map_err(|_| {
                XfrError::ProtocolError(format!("Invalid AAAA record: {}", change.record_value))
            })?;
            builder.add_aaaa_record(&owner_name, ttl, addr)?;
        }
        "CNAME" => {
            builder.add_cname_record(&owner_name, ttl, &change.record_value)?;
        }
        "MX" => {
            let priority = change.record_priority.unwrap_or(10) as u16;
            builder.add_mx_record(&owner_name, ttl, priority, &change.record_value)?;
        }
        "NS" => {
            builder.add_ns_record(&owner_name, ttl, &change.record_value)?;
        }
        "TXT" => {
            builder.add_txt_record(&owner_name, ttl, &change.record_value)?;
        }
        _ => {
            log_info!("Skipping unsupported record type: {}", change.record_type);
        }
    }

    Ok(())
}

fn normalize_change_name(name: &str, zone: &str) -> String {
    if name.ends_with('.') {
        return name.to_string();
    }

    let zone_trimmed = zone.trim_end_matches('.');
    if name == "@" {
        return format!("{}.", zone_trimmed);
    }

    let owner_trimmed = name.trim_end_matches('.');
    let zone_suffix = format!(".{}", zone_trimmed.to_ascii_lowercase());
    let owner_lower = owner_trimmed.to_ascii_lowercase();
    if owner_lower == zone_trimmed.to_ascii_lowercase() || owner_lower.ends_with(&zone_suffix) {
        return format!("{}.", owner_trimmed);
    }

    format!("{}.{}.", owner_trimmed, zone_trimmed)
}

#[cfg(test)]
mod tests {
    use super::normalize_change_name;

    #[test]
    fn normalize_relative_name() {
        assert_eq!(
            normalize_change_name("www", "example.com"),
            "www.example.com."
        );
    }

    #[test]
    fn normalize_apex_name() {
        assert_eq!(normalize_change_name("@", "example.com."), "example.com.");
    }

    #[test]
    fn keep_fqdn_name() {
        assert_eq!(
            normalize_change_name("api.example.com.", "example.com"),
            "api.example.com."
        );
    }
}
