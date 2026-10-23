//! Encode and stream the service's virtual catalog as AXFR or IXFR.

use bindizr_core::dns::{CatalogZone, Serial, message, message::Rtype, tsig::TransferSigner};

use crate::dns::{error::DnsError, stream::ResponseWriter};

/// Answer a catalog transfer with its current SOA or full snapshot.
pub(crate) async fn send_catalog_response(
    writer: &ResponseWriter,
    query: &message::ParsedQuery,
    response_qtype: Rtype,
    signer: &mut Option<TransferSigner>,
    content: (CatalogZone, Vec<String>),
) -> Result<(), DnsError> {
    let (catalog_zone, member_zones) = content;
    log::info!(
        "{} request for catalog zone: {}",
        response_qtype,
        catalog_zone.name
    );

    let mut builder = message::DnsMessageBuilder::new(query, response_qtype);

    if let Some(signer) = signer.take() {
        builder = builder.sign_with(signer);
    }

    let streamed = async {
        let mut messages_sent = 0usize;

        let serial = catalog_zone.serial;

        writer
            .add_answer_and_flush_if_needed(&mut builder, &mut messages_sent, |builder| {
                builder.add_catalog_soa(&catalog_zone)
            })
            .await?;

        // RFC 1995, Section 2: equal or newer clients need only the current SOA.
        if response_qtype == Rtype::IXFR
            && query.client_serial.is_some_and(|client| {
                let client = Serial::from(client);
                client == serial || client.is_newer_than(serial)
            })
        {
            return writer.flush_if_not_empty(&mut builder).await;
        }

        writer
            .add_answer_and_flush_if_needed(&mut builder, &mut messages_sent, |builder| {
                builder.add_catalog_ns(&catalog_zone)
            })
            .await?;
        writer
            .add_answer_and_flush_if_needed(&mut builder, &mut messages_sent, |builder| {
                builder.add_catalog_schema_version(&catalog_zone)
            })
            .await?;

        // Member PTRs tell secondaries which zones this catalog provisions.
        for member_zone in &member_zones {
            writer
                .add_answer_and_flush_if_needed(&mut builder, &mut messages_sent, |builder| {
                    builder.add_catalog_ptr(&catalog_zone, member_zone)
                })
                .await?;
        }

        // Close the catalog snapshot before flushing its final envelope.
        writer
            .add_answer_and_flush_if_needed(&mut builder, &mut messages_sent, |builder| {
                builder.add_catalog_soa(&catalog_zone)
            })
            .await?;
        messages_sent += writer.flush_if_not_empty(&mut builder).await?;

        Ok::<usize, DnsError>(messages_sent)
    }
    .await;

    // Handed back so a failure's SERVFAIL is signed too.
    *signer = builder.take_signer();
    let messages_sent = streamed?;

    log::info!(
        "Catalog {} completed at serial {} in {} DNS message(s)",
        response_qtype,
        catalog_zone.serial,
        messages_sent
    );

    Ok(())
}
