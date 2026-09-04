use chrono::Utc;

use super::*;

fn grant(pattern: &str, types: &str) -> TsigGrant {
    TsigGrant {
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
