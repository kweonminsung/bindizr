use super::{catalog, error::XfrError, wire};
use crate::{
    log_info,
    service::{record::RecordService, zone::ZoneService},
};
use domain::base::{Name, iana::Rtype};
use std::net::IpAddr;
use tokio::net::TcpStream;

/// Handle AXFR
pub(crate) async fn handle_axfr(
    stream: &mut TcpStream,
    zone_name: &Name<Vec<u8>>,
    query_id: u16,
    client_ip: IpAddr,
) -> Result<(), XfrError> {
    handle_axfr_with_qtype(stream, zone_name, query_id, client_ip, Rtype::AXFR).await
}

/// Handle AXFR payload with a specific response question type.
/// IXFR fallback should keep QTYPE=IXFR to match the original query.
pub(crate) async fn handle_axfr_with_qtype(
    stream: &mut TcpStream,
    zone_name: &Name<Vec<u8>>,
    query_id: u16,
    client_ip: IpAddr,
    response_qtype: Rtype,
) -> Result<(), XfrError> {
    log_info!(
        "AXFR request for zone {:?} from {}",
        zone_name.to_string(),
        client_ip
    );

    let zone_name_owned = zone_name.to_string();
    let zone_name_str = zone_name_owned.trim_end_matches('.');

    // Check if this is a catalog zone request
    if catalog::is_catalog_zone(zone_name_str) {
        return catalog::handle_catalog_axfr_with_qtype(
            stream,
            zone_name,
            query_id,
            response_qtype,
        )
        .await;
    }

    let zone = ZoneService::find(zone_name_str)
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))?
        .ok_or_else(|| XfrError::ZoneNotFound(zone_name_str.to_string()))?;

    let records = RecordService::list_by_zone_id(zone.id)
        .await
        .map_err(|e| XfrError::DatabaseError(e.to_string()))?;

    log_info!(
        "AXFR: zone {} has {} records, serial={}",
        zone_name_str,
        records.len(),
        zone.serial
    );

    // Build and send AXFR response across one or more TCP DNS messages.
    let mut builder = wire::DnsMessageBuilder::new(query_id, zone_name, response_qtype);
    let mut messages_sent = 0usize;

    // Add initial SOA record
    messages_sent += wire::add_answer_and_flush_if_needed(stream, &mut builder, |builder| {
        builder.add_soa(&zone, zone.serial as u32)
    })
    .await?;

    // Add all records
    for record in &records {
        messages_sent += wire::add_answer_and_flush_if_needed(stream, &mut builder, |builder| {
            builder.add_record(record, &zone.name)
        })
        .await?;
    }

    // Add final SOA record to indicate end of transfer
    messages_sent += wire::add_answer_and_flush_if_needed(stream, &mut builder, |builder| {
        builder.add_soa(&zone, zone.serial as u32)
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
