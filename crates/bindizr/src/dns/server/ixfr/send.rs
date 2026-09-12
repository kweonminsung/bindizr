//! Writing the delta out: the SOA-delimited framing of RFC 1995, Section 4
//! and one journal row rendered as one wire RR.

use std::collections::HashMap;

use bindizr_core::{
    dns::{message, message::Rtype, name::ZoneName},
    log_info,
    model::{
        zone::Zone,
        zone_change::{ChangeOperation, JournalRecordType, ZoneChange},
        zone_version::ZoneVersion,
    },
};
use tokio::net::TcpStream;

use crate::dns::error::XfrError;

/// The whole answer when the client is already at the current serial: one
/// SOA and nothing to replay (RFC 1995, Section 2).
pub(crate) async fn send_soa_response(
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
pub(crate) enum IxfrSendError {
    /// Failed before writing anything — safe to fall back to AXFR.
    NotStarted(XfrError),
    /// Failed mid-stream; falling back to AXFR would corrupt the partial IXFR.
    Partial(XfrError),
}

/// Streams the IXFR answers across multiple TCP messages, flushing before the
/// 64 KiB wire limit, and reports whether a failure left the stream dirty so
/// the caller can decide about AXFR fallback.
pub(crate) async fn send_ixfr_response(
    stream: &mut TcpStream,
    query: &message::ParsedQuery,
    zone: &Zone,
    client_serial: u32,
    changes: &[ZoneChange],
    versions_by_serial: &HashMap<u32, ZoneVersion>,
) -> Result<(), IxfrSendError> {
    let mut builder = message::DnsMessageBuilder::new(query.query_id, &query.qname, Rtype::IXFR);
    let mut messages_sent = 0usize;

    let result = async {
        let current_version = versions_by_serial
            .get(&bindizr_core::dns::serial_to_u32(zone.serial)?)
            .ok_or_else(|| {
                XfrError::ProtocolError("Missing current serial SOA version for IXFR".to_string())
            })?;

        // Initial SOA (current serial).
        crate::dns::wire::add_answer_and_flush_if_needed(
            &mut builder,
            stream,
            &mut messages_sent,
            |builder| builder.add_version_soa(current_version),
        )
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
                XfrError::ProtocolError(format!(
                    "Missing old SOA version for serial {}",
                    old_serial
                ))
            })?;
            crate::dns::wire::add_answer_and_flush_if_needed(
                &mut builder,
                stream,
                &mut messages_sent,
                |builder| builder.add_version_soa(old_soa),
            )
            .await?;

            for change in serial_changes
                .iter()
                .filter(|c| c.operation == ChangeOperation::Del)
            {
                crate::dns::wire::add_answer_and_flush_if_needed(
                    &mut builder,
                    stream,
                    &mut messages_sent,
                    |builder| add_change(builder, change, &zone.name),
                )
                .await?;
            }

            // New SOA (addition section marker).
            let new_soa = versions_by_serial.get(&serial).ok_or_else(|| {
                XfrError::ProtocolError(format!("Missing new SOA version for serial {}", serial))
            })?;
            crate::dns::wire::add_answer_and_flush_if_needed(
                &mut builder,
                stream,
                &mut messages_sent,
                |builder| builder.add_version_soa(new_soa),
            )
            .await?;

            for change in serial_changes
                .iter()
                .filter(|c| c.operation == ChangeOperation::Add)
            {
                crate::dns::wire::add_answer_and_flush_if_needed(
                    &mut builder,
                    stream,
                    &mut messages_sent,
                    |builder| add_change(builder, change, &zone.name),
                )
                .await?;
            }
        }

        // Final SOA (current serial).
        crate::dns::wire::add_answer_and_flush_if_needed(
            &mut builder,
            stream,
            &mut messages_sent,
            |builder| builder.add_version_soa(current_version),
        )
        .await?;
        messages_sent += crate::dns::wire::flush_if_not_empty(&mut builder, stream).await?;

        Ok::<(), XfrError>(())
    }
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
