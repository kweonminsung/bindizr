use std::{collections::HashMap, net::IpAddr};

use bindizr_core::dns::name::to_owner_fqdn;
use domain::base::{Name, iana::Rtype};
use tokio::net::TcpStream;

use super::{axfr, catalog, delta};
use crate::{error::XfrError, log_info, log_warn, service::zone::ZoneService, wire};

/// Handles an IXFR request.
pub(crate) async fn handle_ixfr(
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

    // Catalog zones fall back to AXFR.
    if catalog::is_catalog_zone(zone_name_str) {
        log_info!("IXFR: Catalog zone requested, falling back to AXFR");
        return axfr::handle_axfr_with_qtype(stream, zone_name, query_id, client_ip, Rtype::IXFR)
            .await;
    }

    let zone = ZoneService::find(zone_name_str)
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))?
        .ok_or_else(|| XfrError::ZoneNotFound(zone_name_str.to_string()))?;

    let current_serial = delta::serial_to_u32(zone.serial)?;

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

    // Client is ahead of us: we can't build a delta, so fall back to AXFR.
    if client_serial > current_serial {
        log_warn!(
            "IXFR: Client serial {} > current serial {}, falling back to AXFR",
            client_serial,
            current_serial
        );
        return axfr::handle_axfr_with_qtype(stream, zone_name, query_id, client_ip, Rtype::IXFR)
            .await;
    }

    let changes = delta::get_zone_changes(zone.id, client_serial, current_serial).await?;

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
    let mut serials_in_changes: Vec<u32> = changes
        .iter()
        .map(|c| delta::serial_to_u32(c.serial))
        .collect::<Result<_, _>>()?;
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

    // All required serials fall within [client_serial, current_serial], so fetch
    // the whole span in one query instead of one round-trip per serial. Any
    // snapshot that is missing is caught by the chain validation below.
    for snapshot in delta::get_zone_snapshots(zone.id, client_serial, current_serial).await? {
        if let Ok(serial) = delta::serial_to_u32(snapshot.serial) {
            snapshots_by_serial.insert(serial, snapshot);
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

    match send_ixfr_response(
        stream,
        zone_name,
        query_id,
        &zone,
        client_serial,
        &changes,
        &snapshots_by_serial,
    )
    .await
    {
        Ok(()) => {}
        // Nothing was written yet, so a full AXFR is still a valid response.
        Err(IxfrSendError::NotStarted(err)) => {
            log_warn!(
                "IXFR: Failed to build incremental response ({}), falling back to AXFR",
                err
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
        // Bytes already sent; a fallback AXFR would corrupt the partial IXFR.
        Err(IxfrSendError::Partial(err)) => {
            log_warn!(
                "IXFR: aborting after partial send, not falling back: {}",
                err
            );
            return Err(err);
        }
    }

    log_info!("IXFR completed for zone {}", zone_name_str);

    Ok(())
}

/// Sends a single-SOA response when the client is already up-to-date.
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

/// Outcome of a failed IXFR stream: whether any bytes reached the client yet.
enum IxfrSendError {
    /// Failed before writing anything — safe to fall back to AXFR.
    NotStarted(XfrError),
    /// Failed mid-stream; falling back to AXFR would corrupt the partial IXFR.
    Partial(XfrError),
}

/// Sends an IXFR response with incremental changes, reporting whether a failure
/// left the stream dirty so the caller can decide about AXFR fallback.
async fn send_ixfr_response(
    stream: &mut TcpStream,
    zone_name: &Name<Vec<u8>>,
    query_id: u16,
    zone: &crate::model::zone::Zone,
    client_serial: u32,
    changes: &[delta::ZoneChange],
    snapshots_by_serial: &HashMap<u32, delta::ZoneSnapshot>,
) -> Result<(), IxfrSendError> {
    let mut builder = wire::DnsMessageBuilder::new(query_id, zone_name, Rtype::IXFR);
    let mut messages_sent = 0usize;

    let result = stream_ixfr_body(
        stream,
        &mut builder,
        &mut messages_sent,
        zone,
        client_serial,
        changes,
        snapshots_by_serial,
    )
    .await;

    match result {
        Ok(()) => {
            log_info!("IXFR: sent response in {} DNS message(s)", messages_sent);
            Ok(())
        }
        // A failure after the first flush leaves the stream mid-transfer.
        Err(err) if messages_sent > 0 => Err(IxfrSendError::Partial(err)),
        Err(err) => Err(IxfrSendError::NotStarted(err)),
    }
}

/// Streams the IXFR answers across multiple TCP messages, flushing before the
/// 64 KiB wire limit like AXFR. `messages_sent` lets the caller tell a pre-write
/// failure from a mid-stream one.
async fn stream_ixfr_body(
    stream: &mut TcpStream,
    builder: &mut wire::DnsMessageBuilder,
    messages_sent: &mut usize,
    zone: &crate::model::zone::Zone,
    client_serial: u32,
    changes: &[delta::ZoneChange],
    snapshots_by_serial: &HashMap<u32, delta::ZoneSnapshot>,
) -> Result<(), XfrError> {
    let current_snapshot = snapshots_by_serial
        .get(&delta::serial_to_u32(zone.serial)?)
        .ok_or_else(|| {
            XfrError::ProtocolError("Missing current serial SOA snapshot for IXFR".to_string())
        })?;

    // Initial SOA (current serial).
    wire::add_answer_and_flush_if_needed(stream, builder, messages_sent, |builder| {
        builder.add_soa_from_snapshot(current_snapshot)
    })
    .await?;

    let mut changes_by_serial: HashMap<u32, Vec<&delta::ZoneChange>> = HashMap::new();
    for change in changes {
        let serial = delta::serial_to_u32(change.serial)?;
        changes_by_serial.entry(serial).or_default().push(change);
    }

    let mut serials: Vec<u32> = changes_by_serial.keys().copied().collect();
    serials.sort();

    for (idx, &serial) in serials.iter().enumerate() {
        let serial_changes = &changes_by_serial[&serial];

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
        wire::add_answer_and_flush_if_needed(stream, builder, messages_sent, |builder| {
            builder.add_soa_from_snapshot(old_soa)
        })
        .await?;

        for change in serial_changes.iter().filter(|c| c.operation == "DEL") {
            wire::add_answer_and_flush_if_needed(stream, builder, messages_sent, |builder| {
                add_change_to_builder(builder, change, &zone.name)
            })
            .await?;
        }

        // Add new SOA (addition section marker)
        let new_soa = snapshots_by_serial.get(&serial).ok_or_else(|| {
            XfrError::ProtocolError(format!("Missing new SOA snapshot for serial {}", serial))
        })?;
        wire::add_answer_and_flush_if_needed(stream, builder, messages_sent, |builder| {
            builder.add_soa_from_snapshot(new_soa)
        })
        .await?;

        for change in serial_changes.iter().filter(|c| c.operation == "ADD") {
            wire::add_answer_and_flush_if_needed(stream, builder, messages_sent, |builder| {
                add_change_to_builder(builder, change, &zone.name)
            })
            .await?;
        }
    }

    // Final SOA (current serial) closes the transfer.
    wire::add_answer_and_flush_if_needed(stream, builder, messages_sent, |builder| {
        builder.add_soa_from_snapshot(current_snapshot)
    })
    .await?;
    *messages_sent += wire::flush_message_if_not_empty(stream, builder).await?;

    Ok(())
}

/// Adds a zone change record to the message builder.
fn add_change_to_builder(
    builder: &mut wire::DnsMessageBuilder,
    change: &delta::ZoneChange,
    zone_name: &str,
) -> Result<(), XfrError> {
    let ttl = change.record_ttl.unwrap_or(3600) as u32;
    let owner_name = to_owner_fqdn(&change.record_name, zone_name);

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
            let (priority, target) =
                wire::parse_mx_record_value(&change.record_value, change.record_priority)?;
            builder.add_mx_record(&owner_name, ttl, priority, target)?;
        }
        "NS" => {
            builder.add_ns_record(&owner_name, ttl, &change.record_value)?;
        }
        "PTR" => {
            builder.add_ptr_record(&owner_name, ttl, &change.record_value)?;
        }
        "SRV" => {
            let (priority, weight, port, target) =
                wire::parse_srv_record_value(&change.record_value, change.record_priority)?;
            builder.add_srv_record(&owner_name, ttl, priority, weight, port, target)?;
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
