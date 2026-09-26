use bindizr_core::dns::name::ZoneName;

use super::{DynamicUpdateError, parse_update_owner};

/// Verify that owner in zone reduces an in zone owner to its stored form.
#[test]
fn parse_owner_in_zone_reduces_an_in_zone_owner_to_its_stored_form() {
    assert_eq!(
        parse_update_owner("www.example.com.", &ZoneName::from_row("example.com"))
            .unwrap()
            .to_stored(),
        "www"
    );
    assert!(
        parse_update_owner("example.com.", &ZoneName::from_row("example.com"))
            .unwrap()
            .is_apex()
    );
    // A dotted wire label is one label, so it is data rather than a boundary.
    assert_eq!(
        parse_update_owner(
            r"host\.name.example.com.",
            &ZoneName::from_row("example.com")
        )
        .unwrap()
        .labels(),
        ["host.name"]
    );
}

/// Verify that `parse_update_owner` rejects owners outside the zone.
#[test]
fn parse_owner_in_zone_rejects_owners_outside_the_zone() {
    for owner in [
        "aexample.com.",
        "badexample.com.",
        "www.badexample.com.",
        ".",
        // One label spelling the zone is not inside it.
        r"evil\.example.com.",
    ] {
        let err = parse_update_owner(owner, &ZoneName::from_row("example.com")).unwrap_err();
        assert!(matches!(err, DynamicUpdateError::NotZone(_)), "{owner:?}");
    }
}
