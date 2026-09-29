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
mod tests;
