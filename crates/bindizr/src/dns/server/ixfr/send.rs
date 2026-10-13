//! Write SOA-delimited IXFR streams (RFC 1995, Section 4).

use std::collections::HashMap;

use bindizr_core::{
    dns::{Serial, message, message::Rtype, tsig::TransferSigner},
    model::{
        zone::Zone,
        zone_change::{ChangeOperation, ZoneChange},
        zone_version::ZoneVersion,
    },
};
use thiserror::Error;

use crate::dns::{error::DnsError, stream::ResponseWriter};

/// Send the current SOA alone (RFC 1995, Section 2).
pub(crate) async fn send_soa_response(
    writer: &ResponseWriter,
    query: &message::ParsedQuery,
    zone: &Zone,
    signer: Option<TransferSigner>,
) -> Result<(), DnsError> {
    let mut builder = message::DnsMessageBuilder::new(query, Rtype::IXFR);
    if let Some(signer) = signer {
        builder = builder.sign_with(signer);
    }

    builder.add_soa(zone, zone.serial)?;
    writer.flush_if_not_empty(&mut builder).await?;

    Ok(())
}

/// Outcome of a failed IXFR stream: whether any bytes reached the client yet.
#[derive(Debug, Error)]
pub(crate) enum SendIxfrError {
    /// No bytes sent; AXFR may reuse the signer.
    #[error("{error}")]
    NotStarted {
        #[source]
        error: DnsError,
        /// Boxed: a signing context dwarfs the error beside it.
        signer: Option<Box<TransferSigner>>,
    },
    /// Bytes may have been sent; AXFR would corrupt the stream.
    #[error("{error}")]
    Partial {
        #[source]
        error: DnsError,
        signer: Option<Box<TransferSigner>>,
    },
}

/// Stream IXFR within the message limit, reporting whether failure permits AXFR.
pub(crate) async fn send_ixfr_response(
    writer: &ResponseWriter,
    query: &message::ParsedQuery,
    zone: &Zone,
    client_serial: Serial,
    changes: &[ZoneChange],
    versions_by_serial: &HashMap<Serial, ZoneVersion>,
    signer: Option<TransferSigner>,
) -> Result<(), SendIxfrError> {
    let mut builder = message::DnsMessageBuilder::new(query, Rtype::IXFR);
    if let Some(signer) = signer {
        builder = builder.sign_with(signer);
    }
    let mut messages_sent = 0usize;

    let result = async {
        let current_version =
            versions_by_serial
                .get(&zone.serial)
                .ok_or(DnsError::MissingVersion {
                    which: "current serial",
                    serial: zone.serial,
                })?;

        // Initial SOA (current serial).
        writer
            .add_answer_and_flush_if_needed(&mut builder, &mut messages_sent, |builder| {
                builder.add_version_soa(current_version)
            })
            .await?;

        let mut changes_by_serial: HashMap<Serial, Vec<&ZoneChange>> = HashMap::new();
        for change in changes {
            let serial = change.serial;
            changes_by_serial.entry(serial).or_default().push(change);
        }

        let mut serials: Vec<Serial> = changes_by_serial.keys().copied().collect();
        serials.sort();

        for (idx, &serial) in serials.iter().enumerate() {
            let serial_changes = &changes_by_serial[&serial];

            let old_serial = if idx == 0 {
                client_serial
            } else {
                serials[idx - 1]
            };

            // Old SOA (deletion section marker).
            let old_soa = versions_by_serial
                .get(&old_serial)
                .ok_or(DnsError::MissingVersion {
                    which: "old",
                    serial: old_serial,
                })?;
            writer
                .add_answer_and_flush_if_needed(&mut builder, &mut messages_sent, |builder| {
                    builder.add_version_soa(old_soa)
                })
                .await?;

            for change in serial_changes
                .iter()
                .filter(|c| c.operation == ChangeOperation::Delete)
            {
                writer
                    .add_answer_and_flush_if_needed(&mut builder, &mut messages_sent, |builder| {
                        builder.add_change(change, &zone.name)
                    })
                    .await?;
            }

            // New SOA (addition section marker).
            let new_soa = versions_by_serial
                .get(&serial)
                .ok_or(DnsError::MissingVersion {
                    which: "new",
                    serial,
                })?;
            writer
                .add_answer_and_flush_if_needed(&mut builder, &mut messages_sent, |builder| {
                    builder.add_version_soa(new_soa)
                })
                .await?;

            for change in serial_changes
                .iter()
                .filter(|c| c.operation == ChangeOperation::Add)
            {
                writer
                    .add_answer_and_flush_if_needed(&mut builder, &mut messages_sent, |builder| {
                        builder.add_change(change, &zone.name)
                    })
                    .await?;
            }
        }

        // Final SOA (current serial).
        writer
            .add_answer_and_flush_if_needed(&mut builder, &mut messages_sent, |builder| {
                builder.add_version_soa(current_version)
            })
            .await?;
        messages_sent += writer.flush_if_not_empty(&mut builder).await?;

        Ok::<(), DnsError>(())
    }
    .await;

    match result {
        Ok(()) => {
            log::info!("IXFR: sent response in {} DNS message(s)", messages_sent);
            Ok(())
        }
        // A failure after the first flush leaves the stream mid-transfer, and
        // so does an I/O failure on the first frame: part of it may be out.
        Err(err)
            if messages_sent > 0
                || matches!(err, DnsError::Io(_) | DnsError::WriteTimeout { .. }) =>
        {
            Err(SendIxfrError::Partial {
                error: err,
                signer: builder.take_signer().map(Box::new),
            })
        }
        Err(error) => Err(SendIxfrError::NotStarted {
            error,
            signer: builder.take_signer().map(Box::new),
        }),
    }
}
