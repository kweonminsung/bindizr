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
