use std::net::IpAddr;

use bindizr_core::dns::message::{DnsMessageBuilder, ParsedQuery};
use bindizr_core::model::transfer::TransferKind;
use bindizr_service::zone::TransferAccess;
use bindizr_service::{transfer, zone};

use crate::dns::error::DnsError;
use crate::dns::server::auth::TransferIdentity;
use crate::dns::server::{DnsContext, catalog, transfer_cache};
use crate::dns::stream::ResponseWriter;

/// Send AXFR content with the original QTYPE, including IXFR fallback.
/// Claim the signer only after authorization, leaving it available for refusal responses.
pub(crate) async fn handle_axfr(
    dns_cx: &DnsContext,
    writer: &ResponseWriter,
    client_ip: IpAddr,
    query: &ParsedQuery,
    identity: &mut TransferIdentity,
) -> Result<(), DnsError> {
    let cx = dns_cx.daemon();
    let zone_name_str = query.zone_name.as_str();

    log::info!("AXFR request for zone {zone_name_str:?} from {client_ip}");

    if cx.config().dns.is_catalog_zone(zone_name_str) {
        let access = tokio::select! {
            biased;
            () = writer.failed() => return Err(DnsError::PeerClosed),

            access = zone::refresh_catalog_content(cx, &identity.caller) => access?,
        };
        let content = access.map_err(|refusal| DnsError::Refused {
            reason: refusal.to_string(),
        })?;

        return catalog::send_catalog_response(writer, query, &mut identity.signer, content).await;
    }

    // A name the zone type refuses is answered NOTAUTH like a missing zone.
    let access = match zone::normalize_name(zone_name_str) {
        Ok(zone_name) => {
            tokio::select! {
                biased;
                () = writer.failed() => return Err(DnsError::PeerClosed),

                access = transfer_cache::authorize_transfer_content_by_name(dns_cx, &identity.caller, &zone_name) => access?,
            }
        }
        Err(_) => TransferAccess::NotAuth,
    };
    let (zone, content) = match access {
        TransferAccess::Granted(content) => content,
        TransferAccess::NotAuth => {
            return Err(DnsError::NotAuth {
                zone_name: zone_name_str.to_string(),
            });
        }
        TransferAccess::Refused(refusal) => {
            return Err(DnsError::Refused {
                reason: refusal.to_string(),
            });
        }
    };

    log::info!(
        "AXFR: zone {zone_name_str} has {} records + {} DNSSEC records, serial={}",
        content.records.len(),
        content.dnssec_records.len(),
        zone.serial
    );

    let mut builder = DnsMessageBuilder::new(query);

    if let Some(signer) = identity.signer.take() {
        builder = builder.sign_with(signer);
    }

    // The opening SOA identifies the serial of this content snapshot.
    let serial = zone.serial;

    let streamed = async {
        let mut messages_sent = 0usize;

        writer
            .add_answer_and_flush_if_needed(&mut builder, &mut messages_sent, |builder| {
                builder.add_soa(&zone, serial)
            })
            .await?;

        // The snapshot includes both user records and the derived DNSSEC plane.
        for record in content.records.iter() {
            writer
                .add_answer_and_flush_if_needed(&mut builder, &mut messages_sent, |builder| {
                    builder.add_record(record, &zone.name)
                })
                .await?;
        }

        for record in content.dnssec_records.iter() {
            writer
                .add_answer_and_flush_if_needed(&mut builder, &mut messages_sent, |builder| {
                    builder.add_dnssec_record(record, &zone.name)
                })
                .await?;
        }

        // Final SOA closes the transfer.
        writer
            .add_answer_and_flush_if_needed(&mut builder, &mut messages_sent, |builder| {
                builder.add_soa(&zone, serial)
            })
            .await?;
        messages_sent += writer.flush_if_not_empty(&mut builder).await?;

        Ok::<usize, DnsError>(messages_sent)
    }
    .await;

    // Handed back so a failure's SERVFAIL is signed too.
    identity.signer = builder.take_signer();
    let messages_sent = streamed?;

    log::info!(
        "AXFR completed for zone {zone_name_str}: sent {} records + 2 SOA records in {messages_sent} DNS message(s)",
        content.records.len() + content.dnssec_records.len()
    );

    transfer::save_ok(
        cx,
        client_ip,
        zone.id,
        TransferKind::from_qtype(query.qtype),
        writer.transport(),
        false,
        serial,
    )
    .await;

    Ok(())
}
