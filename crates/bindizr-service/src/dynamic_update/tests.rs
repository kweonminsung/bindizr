use bindizr_core::dns::name::ZoneName;

use super::{DynamicUpdateError, owner_in_zone};

#[test]
fn owner_in_zone_reduces_an_in_zone_owner_to_its_stored_form() {
    assert_eq!(
        owner_in_zone("www.example.com.", &ZoneName::from_row("example.com"))
            .unwrap()
            .to_stored(),
        "www"
    );
    assert!(
        owner_in_zone("example.com.", &ZoneName::from_row("example.com"))
            .unwrap()
            .is_apex()
    );
    // A dotted wire label is one label, so it is data rather than a boundary.
    assert_eq!(
        owner_in_zone(
            r"host\.name.example.com.",
            &ZoneName::from_row("example.com")
        )
        .unwrap()
        .labels(),
        ["host.name"]
    );
}

#[test]
fn owner_in_zone_rejects_owners_outside_the_zone() {
    for owner in [
        "aexample.com.",
        "badexample.com.",
        "www.badexample.com.",
        ".",
        // One label spelling the zone is not inside it.
        r"evil\.example.com.",
    ] {
        let err = owner_in_zone(owner, &ZoneName::from_row("example.com")).unwrap_err();
        assert!(matches!(err, DynamicUpdateError::NotZone(_)), "{owner:?}");
    }
}
