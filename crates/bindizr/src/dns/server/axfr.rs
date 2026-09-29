use std::net::IpAddr;

use bindizr_core::{
    dns::{message, message::Rtype},
    model::transfer::TransferKind,
};
use bindizr_service::{
    transfer,
    zone::{self, TransferAccess},
};
use tokio::net::TcpStream;

use super::{auth::TransferIdentity, catalog, transfer_cache};
use crate::dns::{error::XfrError, server::DnsContext};

/// Handles an AXFR payload under `response_qtype`: the IXFR fallback keeps
/// QTYPE=IXFR to match the original query. The signer in `identity` is claimed
/// only once the zone is granted, so a refusal or a missing zone leaves it for
/// the caller's error response.
pub(crate) async fn handle_axfr(
    dns_cx: &DnsContext,
    stream: &mut TcpStream,
    query: &message::ParsedQuery,
    client_ip: IpAddr,
    response_qtype: Rtype,
    identity: &mut TransferIdentity,
) -> Result<(), XfrError> {
    let cx = dns_cx.daemon();
    let zone_name_str = query.zone_name.as_str();

    log::info!(
        "AXFR request for zone {:?} from {}",
        zone_name_str,
        client_ip
    );

    if cx.config().dns.is_catalog_zone(zone_name_str) {
        return catalog::handle_catalog_axfr(
            dns_cx,
            stream,
            query,
            response_qtype,
            identity.signer.take(),
        )
        .await;
    }

    // A name the zone type refuses is answered NOTAUTH like a missing zone.
    let access = match zone::normalize_name(zone_name_str) {
        Ok(zone_name) => {
            transfer_cache::authorize_transfer_content_by_name(
                dns_cx,
                &zone_name,
                identity.key.as_ref(),
            )
            .await?
        }
        Err(_) => TransferAccess::NotAuth,
    };
    let (zone, content) = match access {
        TransferAccess::Granted(found) => found,
        TransferAccess::NotAuth => {
            return Err(XfrError::NotAuth(zone_name_str.to_string()));
        }
        TransferAccess::Refused(reason) => return Err(XfrError::Refused(reason)),
    };

    log::info!(
        "AXFR: zone {} has {} records + {} DNSSEC records, serial={}",
        zone_name_str,
        content.records.len(),
        content.dnssec_records.len(),
        zone.serial
    );

    let mut builder = message::DnsMessageBuilder::new(query.query_id, &query.qname, response_qtype);
    if let Some(signer) = identity.signer.take() {
        builder = builder.sign_with(signer);
    }
    let mut messages_sent = 0usize;

    // The opening SOA identifies the serial of this content snapshot.
    let serial = zone.serial;
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

    log::info!(
        "AXFR completed for zone {}: sent {} records + 2 SOA records in {} DNS message(s)",
        zone_name_str,
        content.records.len() + content.dnssec_records.len(),
        messages_sent
    );
    transfer::save_ok(
        cx,
        client_ip,
        zone.id,
        TransferKind::from_qtype(response_qtype),
        false,
        serial,
    )
    .await;

    Ok(())
}
