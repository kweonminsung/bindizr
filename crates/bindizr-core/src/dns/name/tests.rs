use super::{split_presentation_labels, to_display_owner_fqdn, to_owner_fqdn};

#[test]
fn split_presentation_labels_preserves_escaped_dots_and_rejects_dangling_escape() {
    assert_eq!(
        split_presentation_labels(r"host\.name.example.com").unwrap(),
        vec!["host.name", "example", "com"]
    );
    assert!(split_presentation_labels(r"bad.example.com\").is_err());
}

#[test]
fn to_owner_fqdn_expands_relative_name() {
    assert_eq!(to_owner_fqdn("sub", "example.com"), "sub.example.com.");
    assert_eq!(to_owner_fqdn("www", "example.com."), "www.example.com.");
}

#[test]
fn to_owner_fqdn_keeps_zone_qualified_name() {
    assert_eq!(
        to_owner_fqdn("www.example.com", "example.com."),
        "www.example.com."
    );
    assert_eq!(to_owner_fqdn("example.com", "example.com."), "example.com.");
}

#[test]
fn to_owner_fqdn_handles_fqdn_and_apex() {
    assert_eq!(to_owner_fqdn("sub.", "example.com."), "sub.");
    assert_eq!(
        to_owner_fqdn("api.example.com.", "example.com"),
        "api.example.com."
    );
    assert_eq!(to_owner_fqdn("@", "example.com."), "example.com.");
}

#[test]
fn to_display_owner_fqdn_lowercases_and_qualifies() {
    let zone = "test.example.com";

    assert_eq!(to_display_owner_fqdn("@", zone), "test.example.com.");
    assert_eq!(to_display_owner_fqdn("a1", zone), "a1.test.example.com.");
    assert_eq!(
        to_display_owner_fqdn("_acme-challenge", zone),
        "_acme-challenge.test.example.com."
    );
    assert_eq!(
        to_display_owner_fqdn("A1.Test.Example.Com.", zone),
        "a1.test.example.com."
    );
}
