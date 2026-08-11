use std::net::IpAddr;

use domain::base::iana::Rtype;
use tokio::net::TcpStream;

use super::{catalog, delta, zone_cache};
use crate::{error::XfrError, log_info, service::zone::ZoneService, wire};

/// Handles an AXFR payload under `response_qtype`: the IXFR fallback keeps
/// QTYPE=IXFR to match the original query.
pub(crate) async fn handle_axfr(
    stream: &mut TcpStream,
    query: &wire::ParsedQuery,
    client_ip: IpAddr,
    response_qtype: Rtype,
) -> Result<(), XfrError> {
    let zone_name_str = query.zone_name.as_str();

    log_info!(
        "AXFR request for zone {:?} from {}",
        zone_name_str,
        client_ip
    );

    if catalog::is_catalog_zone(zone_name_str) {
        return catalog::handle_catalog_axfr_with_qtype(stream, query, response_qtype).await;
    }

    let zone = ZoneService::find_by_name(zone_name_str)
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))?
        .ok_or_else(|| XfrError::ZoneNotFound(zone_name_str.to_string()))?;

    let records = zone_cache::list_records(zone.id, zone.serial)
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))?;

    log_info!(
        "AXFR: zone {} has {} records, serial={}",
        zone_name_str,
        records.len(),
        zone.serial
    );

    let mut builder = wire::DnsMessageBuilder::new(query.query_id, &query.qname, response_qtype);
    let mut messages_sent = 0usize;

    let serial = delta::serial_to_u32(zone.serial)?;
    wire::add_answer_and_flush_if_needed(stream, &mut builder, &mut messages_sent, |builder| {
        builder.add_soa(&zone, serial)
    })
    .await?;

    for record in records.iter() {
        wire::add_answer_and_flush_if_needed(stream, &mut builder, &mut messages_sent, |builder| {
            builder.add_record(record, &zone.name)
        })
        .await?;
    }

    // Final SOA closes the transfer.
    wire::add_answer_and_flush_if_needed(stream, &mut builder, &mut messages_sent, |builder| {
        builder.add_soa(&zone, serial)
    })
    .await?;
    messages_sent += wire::flush_message_if_not_empty(stream, &mut builder).await?;

    log_info!(
        "AXFR completed for zone {}: sent {} records + 2 SOA records in {} DNS message(s)",
        zone_name_str,
        records.len(),
        messages_sent
    );

    Ok(())
}
