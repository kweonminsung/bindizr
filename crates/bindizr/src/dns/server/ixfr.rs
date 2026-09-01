use std::{collections::HashMap, net::IpAddr};

use bindizr_core::{
    dns::{message, message::Rtype, name::ZoneName},
    log_info, log_warn,
    model::{
        zone_change::{ChangeOperation, JournalRecordType, ZoneChange},
        zone_version::ZoneVersion,
    },
};
use bindizr_service::zone::ZoneService;
use tokio::net::TcpStream;

use super::{axfr, catalog};
use crate::dns::error::XfrError;

/// Handles an IXFR request.
pub(crate) async fn handle_ixfr(
    stream: &mut TcpStream,
    query: &message::ParsedQuery,
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
        .await?
        .ok_or_else(|| XfrError::ZoneNotFound(zone_name_str.to_string()))?;

    let current_serial = bindizr_core::dns::serial_to_u32(zone.serial)?;

    let client_serial = match query.client_serial {
        Some(s) => s,
        None => {
            log_warn!("IXFR: No client serial provided, falling back to AXFR");
            return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR).await;
        }
    };

    if client_serial == current_serial {
        log_info!("IXFR: Client is up-to-date (serial={})", current_serial);
        let current_soa =
            match ZoneService::find_version_by_serial(zone.id, current_serial as i32).await? {
                Some(version) => version,
                None => {
                    log_warn!("IXFR: Missing SOA version, falling back to AXFR");
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

    let changes = ZoneService::list_journal_between_serials(
        zone.id,
        client_serial as i32,
        current_serial as i32,
    )
    .await?;

    if changes.is_empty() {
        log_warn!(
            "IXFR: No history available for serial {} to {}, falling back to AXFR",
            client_serial,
            current_serial
        );
        return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR).await;
    }

    let mut journal_serials: Vec<u32> = changes
        .iter()
        .map(|c| bindizr_core::dns::serial_to_u32(c.serial))
        .collect::<Result<_, _>>()?;
    journal_serials.sort_unstable();
    journal_serials.dedup();

    if let Some(&last_serial) = journal_serials.last()
        && last_serial != current_serial
    {
        log_warn!(
            "IXFR: Last change serial {} != current serial {}, falling back to AXFR",
            last_serial,
            current_serial
        );
        return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR).await;
    }

    let mut versions_by_serial: HashMap<u32, ZoneVersion> = HashMap::new();
    versions_by_serial.reserve(journal_serials.len() + 1);

    for version in ZoneService::list_versions_in_serial_range(
        zone.id,
        client_serial as i32,
        current_serial as i32,
    )
    .await?
    {
        if let Ok(serial) = bindizr_core::dns::serial_to_u32(version.serial) {
            versions_by_serial.insert(serial, version);
        }
    }

    // The version rows are the authoritative list of serials the zone passed
    // through; a journal skipping any of them (a partially pruned history)
    // would replay an incomplete delta as if it were whole.
    let mut version_serials: Vec<u32> = versions_by_serial
        .keys()
        .copied()
        .filter(|&serial| serial > client_serial)
        .collect();
    version_serials.sort_unstable();
    if journal_serials != version_serials {
        log_warn!(
            "IXFR: Journal covers serials {:?} but versions after {} are {:?}, falling back to AXFR",
            journal_serials,
            client_serial,
            version_serials
        );
        return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR).await;
    }

    // With the serial sets equal, every delta step has its new SOA version;
    // only the client's own, the first step's old SOA, can still be missing.
    if !versions_by_serial.contains_key(&client_serial) {
        log_warn!(
            "IXFR: Missing SOA version for client serial {}, falling back to AXFR",
            client_serial
        );
        return axfr::handle_axfr(stream, query, client_ip, Rtype::IXFR).await;
    }

    log_info!(
        "IXFR: Sending {} changes across {} serial steps from {} to {}",
        changes.len(),
        journal_serials.len(),
        client_serial,
        current_serial
    );

    match send_ixfr_response(
        stream,
        query,
        &zone,
        client_serial,
        &changes,
        &versions_by_serial,
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
    query: &message::ParsedQuery,
    current_soa: &ZoneVersion,
) -> Result<(), XfrError> {
    let mut builder = message::DnsMessageBuilder::new(query.query_id, &query.qname, Rtype::IXFR);

    builder.add_version_soa(current_soa)?;
    crate::dns::wire::flush_if_not_empty(&mut builder, stream).await?;

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
    query: &message::ParsedQuery,
    zone: &bindizr_core::model::zone::Zone,
    client_serial: u32,
    changes: &[ZoneChange],
    versions_by_serial: &HashMap<u32, ZoneVersion>,
) -> Result<(), IxfrSendError> {
    let mut builder = message::DnsMessageBuilder::new(query.query_id, &query.qname, Rtype::IXFR);
    let mut messages_sent = 0usize;

    let result = stream_ixfr_body(
        stream,
        &mut builder,
        &mut messages_sent,
        zone,
        client_serial,
        changes,
        versions_by_serial,
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
    builder: &mut message::DnsMessageBuilder,
    messages_sent: &mut usize,
    zone: &bindizr_core::model::zone::Zone,
    client_serial: u32,
    changes: &[ZoneChange],
    versions_by_serial: &HashMap<u32, ZoneVersion>,
) -> Result<(), XfrError> {
    let current_version = versions_by_serial
        .get(&bindizr_core::dns::serial_to_u32(zone.serial)?)
        .ok_or_else(|| {
            XfrError::ProtocolError("Missing current serial SOA version for IXFR".to_string())
        })?;

    // Initial SOA (current serial).
    crate::dns::wire::add_answer_and_flush_if_needed(builder, stream, messages_sent, |builder| {
        builder.add_version_soa(current_version)
    })
    .await?;

    let mut changes_by_serial: HashMap<u32, Vec<&ZoneChange>> = HashMap::new();
    for change in changes {
        let serial = bindizr_core::dns::serial_to_u32(change.serial)?;
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
        let old_soa = versions_by_serial.get(&old_serial).ok_or_else(|| {
            XfrError::ProtocolError(format!("Missing old SOA version for serial {}", old_serial))
        })?;
        crate::dns::wire::add_answer_and_flush_if_needed(
            builder,
            stream,
            messages_sent,
            |builder| builder.add_version_soa(old_soa),
        )
        .await?;

        for change in serial_changes
            .iter()
            .filter(|c| c.operation == ChangeOperation::Del)
        {
            crate::dns::wire::add_answer_and_flush_if_needed(
                builder,
                stream,
                messages_sent,
                |builder| add_change(builder, change, &zone.name),
            )
            .await?;
        }

        // New SOA (addition section marker).
        let new_soa = versions_by_serial.get(&serial).ok_or_else(|| {
            XfrError::ProtocolError(format!("Missing new SOA version for serial {}", serial))
        })?;
        crate::dns::wire::add_answer_and_flush_if_needed(
            builder,
            stream,
            messages_sent,
            |builder| builder.add_version_soa(new_soa),
        )
        .await?;

        for change in serial_changes
            .iter()
            .filter(|c| c.operation == ChangeOperation::Add)
        {
            crate::dns::wire::add_answer_and_flush_if_needed(
                builder,
                stream,
                messages_sent,
                |builder| add_change(builder, change, &zone.name),
            )
            .await?;
        }
    }

    // Final SOA (current serial).
    crate::dns::wire::add_answer_and_flush_if_needed(builder, stream, messages_sent, |builder| {
        builder.add_version_soa(current_version)
    })
    .await?;
    *messages_sent += crate::dns::wire::flush_if_not_empty(builder, stream).await?;

    Ok(())
}

fn add_change(
    builder: &mut message::DnsMessageBuilder,
    change: &ZoneChange,
    zone_name: &ZoneName,
) -> Result<(), String> {
    match &change.record_type {
        JournalRecordType::Derived(record_type) => {
            let rdata = change
                .record_rdata
                .clone()
                .ok_or_else(|| "derived change carries no wire rdata".to_string())?;
            builder.add_raw_rdata(
                change.record_name.to_wire(zone_name),
                record_type.wire_type(),
                change.record_ttl as u32,
                rdata,
            )
        }
        JournalRecordType::User(record_type) => {
            let value = change
                .record_value
                .as_deref()
                .ok_or_else(|| "user change carries no record value".to_string())?;
            builder.add_record_parts(
                zone_name,
                &change.record_name,
                record_type,
                value,
                change.record_ttl,
                change.record_priority,
            )
        }
        // The delta's SOA boundaries come from the version rows above.
        JournalRecordType::Soa => Ok(()),
    }
}
