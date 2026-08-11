use std::{collections::HashMap, net::IpAddr};

use bindizr_core::dns::name::ZoneName;
use domain::base::iana::Rtype;
use tokio::net::TcpStream;

use super::{axfr, catalog, delta};
use crate::{error::XfrError, log_info, log_warn, service::zone::ZoneService, wire};

/// Handles an IXFR request.
pub(crate) async fn handle_ixfr(
    stream: &mut TcpStream,
    query: &wire::ParsedQuery,
    client_ip: IpAddr,
) -> Result<(), XfrError> {
    let zone_name_str = query.zone_name.as_str();

    log_info!(
        "IXFR request for zone {:?} from {}, client_serial={:?}",
        zone_name_str,
        client_ip,
        query.client_serial
    );

    if catalog::is_catalog_zone(zone_name_str) {
        log_info!("IXFR: Catalog zone requested, falling back to AXFR");
        return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR).await;
    }

    let zone = ZoneService::find_by_name(zone_name_str)
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))?
        .ok_or_else(|| XfrError::ZoneNotFound(zone_name_str.to_string()))?;

    let current_serial = delta::serial_to_u32(zone.serial)?;

    let client_serial = match query.client_serial {
        Some(s) => s,
        None => {
            log_warn!("IXFR: No client serial provided, falling back to AXFR");
            return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR).await;
        }
    };

    if client_serial == current_serial {
        log_info!("IXFR: Client is up-to-date (serial={})", current_serial);
        let current_soa = match delta::find_zone_snapshot(zone.id, current_serial).await? {
            Some(snapshot) => snapshot,
            None => {
                log_warn!("IXFR: Missing SOA snapshot, falling back to AXFR");
                return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR).await;
            }
        };
        return send_up_to_date_response(stream, query, &current_soa).await;
    }

    if client_serial > current_serial {
        log_warn!(
            "IXFR: Client serial {} > current serial {}, falling back to AXFR",
            client_serial,
            current_serial
        );
        return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR).await;
    }

    let changes = delta::list_zone_changes(zone.id, client_serial, current_serial).await?;

    if changes.is_empty() {
        log_warn!(
            "IXFR: No history available for serial {} to {}, falling back to AXFR",
            client_serial,
            current_serial
        );
        return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR).await;
    }

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
            return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR).await;
        }
        previous_serial = serial;
    }

    if let Some(&last_serial) = serials_in_changes.last()
        && last_serial != current_serial
    {
        log_warn!(
            "IXFR: Last change serial {} != current serial {}, falling back to AXFR",
            last_serial,
            current_serial
        );
        return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR).await;
    }

    let mut snapshots_by_serial: HashMap<u32, delta::ZoneSnapshot> = HashMap::new();
    snapshots_by_serial.reserve(serials_in_changes.len() + 1);

    // Fetch the whole serial span in one query; missing snapshots are caught
    // by the chain validation below.
    for snapshot in delta::list_zone_snapshots(zone.id, client_serial, current_serial).await? {
        if let Ok(serial) = delta::serial_to_u32(snapshot.serial) {
            snapshots_by_serial.insert(serial, snapshot);
        }
    }

    // Every delta step needs both its old and new SOA snapshots.
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
            return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR).await;
        }
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
        query,
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
            return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR).await;
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
    query: &wire::ParsedQuery,
    current_soa: &delta::ZoneSnapshot,
) -> Result<(), XfrError> {
    let mut builder = wire::DnsMessageBuilder::new(query.query_id, &query.qname, Rtype::IXFR);

    builder.add_soa_from_snapshot(current_soa)?;
    wire::flush_message_if_not_empty(stream, &mut builder).await?;

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
    query: &wire::ParsedQuery,
    zone: &crate::model::zone::Zone,
    client_serial: u32,
    changes: &[delta::ZoneChange],
    snapshots_by_serial: &HashMap<u32, delta::ZoneSnapshot>,
) -> Result<(), IxfrSendError> {
    let mut builder = wire::DnsMessageBuilder::new(query.query_id, &query.qname, Rtype::IXFR);
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
/// 64 KiB wire limit. `messages_sent` distinguishes a pre-write failure from a
/// mid-stream one.
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

        // Old SOA (deletion section marker).
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

        for change in serial_changes
            .iter()
            .filter(|c| c.operation == delta::ZoneChange::OP_DEL)
        {
            wire::add_answer_and_flush_if_needed(stream, builder, messages_sent, |builder| {
                add_change(builder, change, &zone.name)
            })
            .await?;
        }

        // New SOA (addition section marker).
        let new_soa = snapshots_by_serial.get(&serial).ok_or_else(|| {
            XfrError::ProtocolError(format!("Missing new SOA snapshot for serial {}", serial))
        })?;
        wire::add_answer_and_flush_if_needed(stream, builder, messages_sent, |builder| {
            builder.add_soa_from_snapshot(new_soa)
        })
        .await?;

        for change in serial_changes
            .iter()
            .filter(|c| c.operation == delta::ZoneChange::OP_ADD)
        {
            wire::add_answer_and_flush_if_needed(stream, builder, messages_sent, |builder| {
                add_change(builder, change, &zone.name)
            })
            .await?;
        }
    }

    // Final SOA (current serial).
    wire::add_answer_and_flush_if_needed(stream, builder, messages_sent, |builder| {
        builder.add_soa_from_snapshot(current_snapshot)
    })
    .await?;
    *messages_sent += wire::flush_message_if_not_empty(stream, builder).await?;

    Ok(())
}

fn add_change(
    builder: &mut wire::DnsMessageBuilder,
    change: &delta::ZoneChange,
    zone_name: &ZoneName,
) -> Result<(), XfrError> {
    builder.add_record_parts(
        zone_name,
        &change.record_name,
        &change.record_type,
        &change.record_value,
        change.record_ttl,
        change.record_priority,
    )
}
