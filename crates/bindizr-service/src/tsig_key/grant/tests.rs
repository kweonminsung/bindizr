use chrono::Utc;

use super::*;

/// Build a grant fixture with the requested name and type filters.
fn grant(pattern: &str, types: &str) -> TsigGrant {
    TsigGrant {
        id: 0,
        zone_id: 1,
        tsig_key_id: 1,
        record_name_pattern: pattern.to_string(),
        record_types: types.to_string(),
        can_write: true,
        created_at: Utc::now(),
    }
}

/// Build a TSIG grant fixture that permits reads only.
fn read_only_grant(pattern: &str, types: &str) -> TsigGrant {
    TsigGrant {
        can_write: false,
        ..grant(pattern, types)
    }
}

/// Verify that `authorize_update` requires name and type match.
#[test]
fn authorize_update_requires_name_and_type_match() {
    let grants = vec![grant("*.dyn", "A,AAAA"), grant("@", "*")];

    assert!(authorize_update(
        &grants,
        &OwnerName::from_row("host.dyn"),
        Some(&RecordType::A)
    ));
    assert!(authorize_update(
        &grants,
        &OwnerName::apex(),
        Some(&RecordType::TXT)
    ));
    // Whole-name delete (TYPE ANY) is only covered by unrestricted types.
    assert!(authorize_update(&grants, &OwnerName::apex(), None));
    assert!(!authorize_update(
        &grants,
        &OwnerName::from_row("host.dyn"),
        None
    ));

    assert!(!authorize_update(
        &grants,
        &OwnerName::from_row("host.dyn"),
        Some(&RecordType::TXT)
    ));
    assert!(!authorize_update(
        &grants,
        &OwnerName::from_row("www"),
        Some(&RecordType::A)
    ));
    // A row holding a literal `@` label is a name under the zone, not the
    // apex, so the apex grant must not reach it.
    assert!(!authorize_update(
        &grants,
        &OwnerName::from_row("@"),
        Some(&RecordType::A)
    ));
}

/// Verify that only a grant over the whole zone covers a transfer.
#[test]
fn only_a_grant_over_the_whole_zone_covers_a_transfer() {
    // A transfer hands the zone over whole, so no narrowed grant covers it.
    assert!(!covers_whole_zone(&[grant("*.dyn", "*")]));
    assert!(!covers_whole_zone(&[grant("*", "A,AAAA")]));
    assert!(!covers_whole_zone(&[grant("@", "*")]));

    assert!(covers_whole_zone(&[grant("*", "*")]));
    // A key a secondary holds needs no nsupdate rights to pull the zone.
    assert!(covers_whole_zone(&[read_only_grant("*", "*")]));
}

/// Verify that a read only grant authorizes no update.
#[test]
fn a_read_only_grant_authorizes_no_update() {
    let grants = vec![read_only_grant("*", "*")];

    assert!(!authorize_update(
        &grants,
        &OwnerName::from_row("host"),
        Some(&RecordType::A)
    ));
}

/// Verify that `authorize_prerequisite` narrows a read to the grant's names
/// and types but accepts a read-only grant.
#[test]
fn authorize_prerequisite_reaches_only_what_the_grant_covers() {
    let grants = vec![read_only_grant("*.dyn", "A")];

    assert!(authorize_prerequisite(
        &grants,
        &OwnerName::from_row("host.dyn"),
        Some(&RecordType::A)
    ));
    assert!(!authorize_prerequisite(
        &grants,
        &OwnerName::from_row("host.dyn"),
        Some(&RecordType::TXT)
    ));
    assert!(!authorize_prerequisite(
        &grants,
        &OwnerName::from_row("secret"),
        Some(&RecordType::A)
    ));
    // A whole-name prerequisite asks about every type at the name.
    assert!(!authorize_prerequisite(
        &grants,
        &OwnerName::from_row("host.dyn"),
        None
    ));
    assert!(authorize_prerequisite(
        &[read_only_grant("*", "*")],
        &OwnerName::from_row("secret"),
        None
    ));
}
