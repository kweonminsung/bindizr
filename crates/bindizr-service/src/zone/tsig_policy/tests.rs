use chrono::Utc;

use super::*;

fn policy(pattern: &str, types: &str) -> ZoneTsigPolicy {
    ZoneTsigPolicy {
        id: 0,
        zone_id: 1,
        tsig_key_id: 1,
        record_name_pattern: pattern.to_string(),
        record_types: types.to_string(),
        created_at: Utc::now(),
    }
}

#[test]
fn authorize_update_requires_name_and_type_match() {
    let policies = vec![policy("*.dyn", "A,AAAA"), policy("@", "*")];

    assert!(authorize_update(
        &policies,
        &OwnerName::from_row("host.dyn"),
        Some(&RecordType::A)
    ));
    assert!(authorize_update(
        &policies,
        &OwnerName::from_row("@"),
        Some(&RecordType::TXT)
    ));
    // Whole-name delete (TYPE ANY) is only covered by unrestricted types.
    assert!(authorize_update(&policies, &OwnerName::from_row("@"), None));
    assert!(!authorize_update(
        &policies,
        &OwnerName::from_row("host.dyn"),
        None
    ));

    assert!(!authorize_update(
        &policies,
        &OwnerName::from_row("host.dyn"),
        Some(&RecordType::TXT)
    ));
    assert!(!authorize_update(
        &policies,
        &OwnerName::from_row("www"),
        Some(&RecordType::A)
    ));
    assert!(!authorize_update(
        &policies,
        &OwnerName::from_row(""),
        Some(&RecordType::A)
    ));
}
