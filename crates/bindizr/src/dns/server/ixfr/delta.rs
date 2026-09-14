//! Whether an incremental reply is possible at all: the two questions that
//! send a client to a full transfer instead.

use bindizr_core::model::zone::Zone;
use bindizr_service::zone::ZoneService;

use crate::dns::error::XfrError;

/// RFC 1995, Section 2 lets a server answer with a full transfer once the
/// incremental one stops being smaller. Counting first also keeps a long-absent
/// secondary from pulling its whole absence into memory. Rows, not bytes:
/// summing lengths would read the rows this decides whether to read.
pub(crate) async fn is_delta_no_smaller_than_zone(
    zone: &Zone,
    client_serial: u32,
    current_serial: u32,
) -> Result<bool, XfrError> {
    let delta_rows = ZoneService::count_journal_between_serials(
        zone.id,
        client_serial as i32,
        current_serial as i32,
    )
    .await?;

    Ok(delta_rows >= ZoneService::count_transfer_records(zone.name.as_str()).await?)
}

/// Why the assembled delta cannot be replayed as an IXFR, or `None` when every
/// step from the client's serial to the current one has both journal rows and
/// the SOA version closing it. The version rows are the authoritative list of
/// serials the zone passed through, so a journal skipping one would replay an
/// incomplete delta as whole. `journal_serials` comes sorted and deduplicated.
pub(crate) fn delta_gap(
    client_serial: u32,
    current_serial: u32,
    journal_serials: &[u32],
    version_serials: &[u32],
) -> Option<String> {
    if let Some(&last) = journal_serials.last()
        && last != current_serial
    {
        return Some(format!(
            "journal ends at serial {last} but the zone is at {current_serial}"
        ));
    }

    let mut steps: Vec<u32> = version_serials
        .iter()
        .copied()
        .filter(|&serial| serial > client_serial)
        .collect();
    steps.sort_unstable();
    if journal_serials != steps {
        return Some(format!(
            "journal covers serials {journal_serials:?} but the versions after {client_serial} are {steps:?}"
        ));
    }

    // With the step sets equal, every step has its new SOA version; only the
    // client's own, the first step's old SOA, can still be missing.
    if !version_serials.contains(&client_serial) {
        return Some(format!(
            "no SOA version for the client's serial {client_serial}"
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::delta_gap;

    /// Verify that a delta covering every step replays.
    #[test]
    fn a_delta_covering_every_step_replays() {
        assert_eq!(delta_gap(10, 12, &[11, 12], &[10, 11, 12]), None);
    }

    /// Verify that versions at or below the client serial are not steps.
    #[test]
    fn versions_at_or_below_the_client_serial_are_not_steps() {
        // The range read is inclusive of the client's own serial, and older
        // rows may still sit in it; only what comes after is a delta step.
        assert_eq!(delta_gap(10, 12, &[11, 12], &[8, 9, 10, 11, 12]), None);
    }

    /// Verify that a journal short of the current serial falls back.
    #[test]
    fn a_journal_short_of_the_current_serial_falls_back() {
        // Missing the newest change would leave the secondary claiming a serial
        // it does not hold the records for.
        assert!(delta_gap(10, 12, &[11], &[10, 11, 12]).is_some());
    }

    /// Verify that a journal skipping a step falls back.
    #[test]
    fn a_journal_skipping_a_step_falls_back() {
        // Serial 11 happened — the version row proves it — but its rows are
        // gone, so the delta would silently drop that change.
        assert!(delta_gap(10, 12, &[12], &[10, 11, 12]).is_some());
    }

    /// Verify that a missing SOA for the client serial falls back.
    #[test]
    fn a_missing_soa_for_the_client_serial_falls_back() {
        // The first step's old SOA marker delimits the deletion section
        // (RFC 1995, Section 4), and nothing else can stand in for it.
        assert!(delta_gap(10, 12, &[11, 12], &[11, 12]).is_some());
    }

    /// Verify that the reason names the serials it disagreed on.
    #[test]
    fn the_reason_names_the_serials_it_disagreed_on() {
        let gap = delta_gap(10, 12, &[12], &[10, 11, 12]).unwrap();

        assert!(gap.contains("[12]") && gap.contains("[11, 12]"), "{gap}");
    }
}
