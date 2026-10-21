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
pub enum IxfrPlan {
    /// Equal or newer client serials need only the current SOA.
    SoaOnly,
    /// Complete journal steps and their bounding SOA versions.
    Changes {
        changes: Vec<ZoneChange>,
        versions: Vec<ZoneVersion>,
    },
    /// Nothing incremental, or a delta with a gap: a full transfer answers.
    Full,
}

/// Authorize and select an IXFR response in one read transaction.
pub async fn authorize_ixfr_plan_by_name(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    client_serial: Serial,
) -> Result<TransferAccess<(Zone, IxfrPlan)>, ServiceError> {
    let mut tx = transaction::begin_read_tx(cx, "failed to load the transfer delta").await?;
    let result = async {
        let zone = match authorize_transfer_tx(&mut tx, caller, zone_name).await? {
            TransferAccess::Granted(zone) => zone,
            TransferAccess::NotAuth => return Ok(TransferAccess::NotAuth),
            TransferAccess::Refused(reason) => return Ok(TransferAccess::Refused(reason)),
        };
        let current = zone.serial;

        // RFC 1995, Section 2: equal or newer client serials need only the current SOA.
        let plan = if client_serial == current || client_serial.is_newer_than(current) {
            IxfrPlan::SoaOnly
        } else if !current.is_newer_than(client_serial) {
            // RFC 1982 leaves the half-range distance unordered; send a full snapshot.
            IxfrPlan::Full
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
                IxfrPlan::Full
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
                    IxfrPlan::Full
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
                    journal_serials.sort_unstable_by_key(|serial| {
                        serial.as_u32().wrapping_sub(client_serial.as_u32())
                    });
                    journal_serials.dedup();
                    let version_serials: Vec<Serial> =
                        versions.iter().map(|version| version.serial).collect();

                    match validate_delta(client_serial, current, &journal_serials, &version_serials)
                    {
                        Ok(()) => IxfrPlan::Changes { changes, versions },
                        Err(gap) => {
                            log::warn!(
                                "IXFR of {} from serial {}: {}, answering with AXFR",
                                zone.name,
                                client_serial,
                                gap
                            );
                            IxfrPlan::Full
                        }
                    }
                }
            }
        };

        Ok(TransferAccess::Granted((zone, plan)))
    }
    .await;

    transaction::finish_tx(tx, result, "failed to load the transfer delta").await
}

/// A gap between journal steps and the zone's saved versions.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
enum ValidateDeltaError {
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
) -> Result<(), ValidateDeltaError> {
    if let Some(&last) = journal_serials.last()
        && last != current_serial
    {
        return Err(ValidateDeltaError::JournalEnds {
            last,
            current: current_serial,
        });
    }

    let mut steps: Vec<Serial> = version_serials
        .iter()
        .copied()
        .filter(|&serial| serial.is_newer_than(client_serial))
        .collect();
    steps.sort_unstable_by_key(|serial| serial.as_u32().wrapping_sub(client_serial.as_u32()));

    if journal_serials != steps {
        return Err(ValidateDeltaError::StepsDiffer {
            journal: journal_serials.to_vec(),
            client: client_serial,
            steps,
        });
    }

    // The first deletion section still needs the client's old SOA.
    if !version_serials.contains(&client_serial) {
        return Err(ValidateDeltaError::NoClientVersion {
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

    /// Verify that a delta covering every step is valid.
    #[test]
    fn ixfr_delta_accepts_complete_history() {
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
    fn ixfr_delta_ignores_versions_at_or_before_client_serial() {
        // The inclusive range may contain older versions; only later ones are steps.
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
    fn ixfr_delta_falls_back_when_journal_misses_current_serial() {
        // Incomplete history must not advance the secondary past its content.
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
    fn ixfr_delta_falls_back_when_client_soa_is_missing() {
        // The first deletion section needs the client's SOA (RFC 1995, Section 4).
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
    fn ixfr_delta_reports_missing_step() {
        // The version proves serial 11 occurred; omitting its changes would corrupt the replay.
        let gap = validate_delta(
            Serial::from(10),
            Serial::from(12),
            &serials(&[12]),
            &serials(&[10, 11, 12]),
        )
        .unwrap_err();

        assert!(
            matches!(&gap, ValidateDeltaError::StepsDiffer { journal, steps, .. } if journal == &serials(&[12]) && steps == &serials(&[11, 12])),
            "{gap}"
        );
    }
}
