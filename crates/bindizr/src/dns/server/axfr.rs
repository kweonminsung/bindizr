use std::net::IpAddr;

use bindizr_core::{
    dns::{message, message::Rtype, tsig::TransferSigner},
    log_info,
};
use bindizr_service::zone::ZoneService;
use tokio::net::TcpStream;

use super::{catalog, zone_cache};
use crate::dns::error::XfrError;

/// Handles an AXFR payload under `response_qtype`: the IXFR fallback keeps
/// QTYPE=IXFR to match the original query. `signer` is present when the
/// request arrived signed; it is claimed only once a zone is found, so a
/// missing zone leaves it for the caller's error response.
pub(crate) async fn handle_axfr(
    stream: &mut TcpStream,
    query: &message::ParsedQuery,
    client_ip: IpAddr,
    response_qtype: Rtype,
    signer: &mut Option<TransferSigner>,
) -> Result<(), XfrError> {
    let zone_name_str = query.zone_name.as_str();

    log_info!(
        "AXFR request for zone {:?} from {}",
        zone_name_str,
        client_ip
    );

    if catalog::is_catalog_zone(zone_name_str) {
        return catalog::handle_catalog_axfr_with_qtype(
            stream,
            query,
            response_qtype,
            signer.take(),
        )
        .await;
    }

    // Non-locking pre-read, only to learn the zone id and probe the cache.
    let zone = ZoneService::find_by_name(zone_name_str)
        .await?
        .ok_or_else(|| XfrError::ZoneNotFound(zone_name_str.to_string()))?;

    let (zone, content) = zone_cache::find_zone_content(zone)
        .await?
        .ok_or_else(|| XfrError::ZoneNotFound(zone_name_str.to_string()))?;

    log_info!(
        "AXFR: zone {} has {} records + {} DNSSEC records, serial={}",
        zone_name_str,
        content.records.len(),
        content.dnssec_records.len(),
        zone.serial
    );

    let mut builder = message::DnsMessageBuilder::new(query.query_id, &query.qname, response_qtype);
    if let Some(signer) = signer.take() {
        builder = builder.sign_with(signer);
    }
    let mut messages_sent = 0usize;

    // The opening SOA identifies the serial of this content snapshot.
    let serial = bindizr_core::dns::serial_to_u32(zone.serial)?;
    crate::dns::wire::add_answer_and_flush_if_needed(
        &mut builder,
        stream,
        &mut messages_sent,
        |builder| builder.add_soa(&zone, serial),
    )
    .await?;

    // The snapshot includes both user records and the derived DNSSEC plane.
    for record in content.records.iter() {
        crate::dns::wire::add_answer_and_flush_if_needed(
            &mut builder,
            stream,
            &mut messages_sent,
            |builder| builder.add_record(record, &zone.name),
        )
        .await?;
    }

    for record in content.dnssec_records.iter() {
        crate::dns::wire::add_answer_and_flush_if_needed(
            &mut builder,
            stream,
            &mut messages_sent,
            |builder| builder.add_dnssec_record(record, &zone.name),
        )
        .await?;
    }

    // Final SOA closes the transfer.
    crate::dns::wire::add_answer_and_flush_if_needed(
        &mut builder,
        stream,
        &mut messages_sent,
        |builder| builder.add_soa(&zone, serial),
    )
    .await?;
    messages_sent += crate::dns::wire::flush_if_not_empty(&mut builder, stream).await?;

    log_info!(
        "AXFR completed for zone {}: sent {} records + 2 SOA records in {} DNS message(s)",
        zone_name_str,
        content.records.len() + content.dnssec_records.len(),
        messages_sent
    );

    Ok(())
}
