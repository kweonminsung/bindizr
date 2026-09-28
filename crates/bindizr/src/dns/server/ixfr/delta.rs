//! Whether an incremental reply can be replayed at all: the gap check that
//! sends a client to a full transfer instead.

use bindizr_core::dns::Serial;
use thiserror::Error;

/// Why the assembled delta cannot be replayed as an IXFR. The version rows
/// are the authoritative list of serials the zone passed through, so a
/// journal skipping one would replay an incomplete delta as whole.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum DeltaGap {
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

/// Check that every step from the client's serial to the current one has both
/// journal rows and the SOA version closing it. `journal_serials` comes
/// sorted and deduplicated.
pub(crate) fn delta_gap(
    client_serial: Serial,
    current_serial: Serial,
    journal_serials: &[Serial],
    version_serials: &[Serial],
) -> Result<(), DeltaGap> {
    if let Some(&last) = journal_serials.last()
        && last != current_serial
    {
        return Err(DeltaGap::JournalEnds {
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
        return Err(DeltaGap::StepsDiffer {
            journal: journal_serials.to_vec(),
            client: client_serial,
            steps,
        });
    }

    // With the step sets equal, every step has its new SOA version; only the
    // client's own, the first step's old SOA, can still be missing.
    if !version_serials.contains(&client_serial) {
        return Err(DeltaGap::NoClientVersion {
            client: client_serial,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bindizr_core::dns::Serial;

    use super::{DeltaGap, delta_gap};

    /// Wrap plain numbers as serials.
    fn serials(values: &[u32]) -> Vec<Serial> {
        values.iter().copied().map(Serial::from).collect()
    }

    /// Verify that a delta covering every step replays.
    #[test]
    fn a_delta_covering_every_step_replays() {
        assert_eq!(
            delta_gap(
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
            delta_gap(
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
            delta_gap(
                Serial::from(10),
                Serial::from(12),
                &serials(&[11]),
                &serials(&[10, 11, 12])
            )
            .is_err()
        );
    }

    /// Verify that a journal skipping a step falls back.
    #[test]
    fn a_journal_skipping_a_step_falls_back() {
        // Serial 11 happened — the version row proves it — but its rows are
        // gone, so the delta would silently drop that change.
        assert!(
            delta_gap(
                Serial::from(10),
                Serial::from(12),
                &serials(&[12]),
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
            delta_gap(
                Serial::from(10),
                Serial::from(12),
                &serials(&[11, 12]),
                &serials(&[11, 12])
            )
            .is_err()
        );
    }

    /// Verify that the reason names the serials it disagreed on.
    #[test]
    fn the_reason_names_the_serials_it_disagreed_on() {
        let gap = delta_gap(
            Serial::from(10),
            Serial::from(12),
            &serials(&[12]),
            &serials(&[10, 11, 12]),
        )
        .unwrap_err();
        assert!(
            matches!(&gap, DeltaGap::StepsDiffer { journal, steps, .. } if journal == &serials(&[12]) && steps == &serials(&[11, 12])),
            "{gap}"
        );
    }
}
