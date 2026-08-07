use super::display_record_owner_name;

#[test]
fn display_record_owner_name_returns_absolute_fqdn() {
    let zone = "test.example.com";

    assert_eq!(display_record_owner_name("@", zone), "test.example.com.");
    assert_eq!(
        display_record_owner_name("a1", zone),
        "a1.test.example.com."
    );
    assert_eq!(
        display_record_owner_name("_acme-challenge", zone),
        "_acme-challenge.test.example.com."
    );
    assert_eq!(
        display_record_owner_name("a1.test.example.com.", zone),
        "a1.test.example.com."
    );
}
