//! IXFR response selection and journal validation (RFC 1995).

use bindizr_core::dns::{Serial, name::ZoneName};
use bindizr_db::LockLevel;
use thiserror::Error;

use super::{TransferAccess, authorize_transfer_tx};
use crate::{
    Context,
    authorization::Caller,
    error::ServiceError,
    model::{zone::Zone, zone_change::ZoneChange, zone_version::ZoneVersion},
    transaction,
};

/// What an IXFR from a client's serial is answered with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferDelta {
    /// Equal serials need only the current SOA.
    SoaOnly,
    /// Complete journal steps and their bounding SOA versions.
    Changes {
        changes: Vec<ZoneChange>,
        versions: Vec<ZoneVersion>,
    },
    /// Nothing incremental, or a delta with a gap: a full transfer answers.
    Full,
}

/// Authorize and load an IXFR delta in one read transaction.
pub async fn authorize_transfer_delta_by_name(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    client_serial: Serial,
) -> Result<TransferAccess<(Zone, TransferDelta)>, ServiceError> {
    let mut tx = transaction::begin_read_tx(cx, "failed to load the transfer delta").await?;
    let result = async {
        let zone = match authorize_transfer_tx(&mut tx, caller, zone_name).await? {
            TransferAccess::Granted(zone) => zone,
            TransferAccess::NotAuth => return Ok(TransferAccess::NotAuth),
            TransferAccess::Refused(reason) => return Ok(TransferAccess::Refused(reason)),
        };
        let current = zone.serial;
        // RFC 1995, Section 2: equal serials need only the current SOA.
        let delta = if client_serial == current {
            TransferDelta::SoaOnly
        } else if !current.is_newer_than(client_serial) || client_serial > Serial::MAX_STORED {
            // RFC 1995, Section 2 exception: newer clients receive the full snapshot.
            // Undefined ordering and serials outside stored history also need AXFR.
            TransferDelta::Full
        } else {
            // RFC 1995, Section 2 permits a full transfer when IXFR is no
            // smaller; rows are counted before any history is loaded.
            let rows = bindizr_db::zone_change::count_between_serials_tx(
                &mut tx,
                zone.id,
                client_serial,
                current,
            )
            .await?;
            let zone_rows = bindizr_db::record::count_tx(&mut tx, zone.id).await?
                + bindizr_db::dnssec_record::count_tx(&mut tx, zone.id).await?;
            if rows >= zone_rows {
                TransferDelta::Full
            } else {
                let changes = bindizr_db::zone_change::list_between_serials_tx(
                    &mut tx,
                    zone.id,
                    client_serial,
                    current,
                    LockLevel::Unlocked,
                )
                .await?;
                if changes.is_empty() {
                    TransferDelta::Full
                } else {
                    let versions = bindizr_db::zone_version::list_in_serial_range_tx(
                        &mut tx,
                        zone.id,
                        client_serial,
                        current,
                    )
                    .await?;
                    let mut journal_serials: Vec<Serial> =
                        changes.iter().map(|change| change.serial).collect();
                    journal_serials.sort_unstable();
                    journal_serials.dedup();
                    let version_serials: Vec<Serial> =
                        versions.iter().map(|version| version.serial).collect();
                    match validate_delta(client_serial, current, &journal_serials, &version_serials)
                    {
                        Ok(()) => TransferDelta::Changes { changes, versions },
                        Err(gap) => {
                            log::warn!(
                                "IXFR of {} from serial {}: {}, answering with AXFR",
                                zone.name,
                                client_serial,
                                gap
                            );
                            TransferDelta::Full
                        }
                    }
                }
            }
        };
        Ok(TransferAccess::Granted((zone, delta)))
    }
    .await;
    transaction::finish_tx(tx, result, "failed to load the transfer delta").await
}

/// A gap between journal steps and the zone's saved versions.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
enum ReplayDeltaError {
    #[error("journal ends at serial {last} but the zone is at {current}")]
    JournalEnds { last: Serial, current: Serial },
    #[error("journal covers serials {journal:?} but the versions after {client} are {steps:?}")]
    StepsDiffer {
        journal: Vec<Serial>,
        client: Serial,
        steps: Vec<Serial>,
    },
    #[error("no SOA version for the client's serial {client}")]
    NoClientVersion { client: Serial },
}

/// Check journal coverage and bounding SOAs; `journal_serials` is sorted and unique.
fn validate_delta(
    client_serial: Serial,
    current_serial: Serial,
    journal_serials: &[Serial],
    version_serials: &[Serial],
) -> Result<(), ReplayDeltaError> {
    if let Some(&last) = journal_serials.last()
        && last != current_serial
    {
        return Err(ReplayDeltaError::JournalEnds {
            last,
            current: current_serial,
        });
    }

    let mut steps: Vec<Serial> = version_serials
        .iter()
        .copied()
        .filter(|&serial| serial > client_serial)
        .collect();
    steps.sort_unstable();
    if journal_serials != steps {
        return Err(ReplayDeltaError::StepsDiffer {
            journal: journal_serials.to_vec(),
            client: client_serial,
            steps,
        });
    }

    // With the step sets equal, every step has its new SOA version; only the
    // client's own, the first step's old SOA, can still be missing.
    if !version_serials.contains(&client_serial) {
        return Err(ReplayDeltaError::NoClientVersion {
            client: client_serial,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bindizr_core::dns::Serial;

    use super::*;

    /// Wrap plain numbers as serials.
    fn serials(values: &[u32]) -> Vec<Serial> {
        values.iter().copied().map(Serial::from).collect()
    }

    /// Verify that a delta covering every step replays.
    #[test]
    fn a_delta_covering_every_step_replays() {
        assert_eq!(
            validate_delta(
                Serial::from(10),
                Serial::from(12),
                &serials(&[11, 12]),
                &serials(&[10, 11, 12])
            ),
            Ok(())
        );
    }

    /// Verify that versions at or below the client serial are not steps.
    #[test]
    fn versions_at_or_below_the_client_serial_are_not_steps() {
        // The range read is inclusive of the client's own serial, and older
        // rows may still sit in it; only what comes after is a delta step.
        assert_eq!(
            validate_delta(
                Serial::from(10),
                Serial::from(12),
                &serials(&[11, 12]),
                &serials(&[8, 9, 10, 11, 12])
            ),
            Ok(())
        );
    }

    /// Verify that a journal short of the current serial falls back.
    #[test]
    fn a_journal_short_of_the_current_serial_falls_back() {
        // Missing the newest change would leave the secondary claiming a serial
        // it does not hold the records for.
        assert!(
            validate_delta(
                Serial::from(10),
                Serial::from(12),
                &serials(&[11]),
                &serials(&[10, 11, 12])
            )
            .is_err()
        );
    }

    /// Verify that a missing SOA for the client serial falls back.
    #[test]
    fn a_missing_soa_for_the_client_serial_falls_back() {
        // The first step's old SOA marker delimits the deletion section
        // (RFC 1995, Section 4), and nothing else can stand in for it.
        assert!(
            validate_delta(
                Serial::from(10),
                Serial::from(12),
                &serials(&[11, 12]),
                &serials(&[11, 12])
            )
            .is_err()
        );
    }

    /// Verify that a missing journal step refuses IXFR and identifies the gap.
    #[test]
    fn a_journal_skipping_a_step_reports_the_gap() {
        // The version proves serial 11 occurred; omitting its changes would corrupt the replay.
        let gap = validate_delta(
            Serial::from(10),
            Serial::from(12),
            &serials(&[12]),
            &serials(&[10, 11, 12]),
        )
        .unwrap_err();
        assert!(
            matches!(&gap, ReplayDeltaError::StepsDiffer { journal, steps, .. } if journal == &serials(&[12]) && steps == &serials(&[11, 12])),
            "{gap}"
        );
    }
}
