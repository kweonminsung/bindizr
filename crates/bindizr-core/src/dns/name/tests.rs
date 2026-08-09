use super::{
    escape_presentation_label, is_same_or_subdomain_fqdn, presentation_labels,
    split_presentation_labels, to_display_owner_fqdn, to_encoded_owner_name, to_owner_fqdn,
};

#[test]
fn split_presentation_labels_preserves_escaped_dots_and_rejects_dangling_escape() {
    assert_eq!(
        split_presentation_labels(r"host\.name.example.com").unwrap(),
        vec!["host.name", "example", "com"]
    );
    assert!(split_presentation_labels(r"bad.example.com\").is_err());
}

#[test]
fn escape_presentation_label_round_trips_through_presentation_labels() {
    assert_eq!(escape_presentation_label("plain"), "plain");
    assert_eq!(escape_presentation_label("host.name"), r"host\.name");
    assert_eq!(escape_presentation_label(r"back\slash"), r"back\\slash");

    // A dotted label must stay one label, not read as a label boundary.
    let escaped = format!("{}.example.com", escape_presentation_label("host.name"));
    assert_eq!(
        presentation_labels(&escaped).unwrap().collect::<Vec<_>>(),
        vec!["host.name", "example", "com"]
    );
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
fn to_encoded_owner_name_maps_apex_and_subnames_lowercased() {
    assert_eq!(
        to_encoded_owner_name("example.com.", "example.com").as_deref(),
        Some("@")
    );
    assert_eq!(
        to_encoded_owner_name("@", "example.com.").as_deref(),
        Some("@")
    );
    assert_eq!(
        to_encoded_owner_name("WWW.Example.COM.", "example.com").as_deref(),
        Some("www")
    );
    assert_eq!(
        to_encoded_owner_name("a.b.example.com.", "example.com.").as_deref(),
        Some("a.b")
    );
    assert_eq!(
        to_encoded_owner_name("mail", "example.com").as_deref(),
        Some("mail")
    );
}

#[test]
fn to_encoded_owner_name_strips_the_zone_suffix_once() {
    // Repeated stripping collapsed a repeated-zone owner to an empty name.
    assert_eq!(
        to_encoded_owner_name("example.com.example.com.", "example.com").as_deref(),
        Some("example.com")
    );
}

#[test]
fn to_encoded_owner_name_rejects_names_outside_the_zone() {
    assert_eq!(to_encoded_owner_name("other.org.", "example.com"), None);
    assert_eq!(to_encoded_owner_name("aexample.com.", "example.com"), None);
}

#[test]
fn to_encoded_owner_name_keeps_an_escaped_dot_inside_one_label() {
    assert_eq!(
        to_encoded_owner_name(r"host\.name.example.com.", "example.com").as_deref(),
        Some(r"host\.name")
    );
}

#[test]
fn zone_containment_reads_an_escaped_dot_as_label_content() {
    // The two-label name [evil.example, com] is outside example.com; reading
    // the escape as a boundary would let one label impersonate a subdomain.
    assert!(!is_same_or_subdomain_fqdn(
        r"evil\.example.com.",
        "example.com."
    ));
    assert_eq!(
        to_encoded_owner_name(r"evil\.example.com.", "example.com"),
        None
    );

    assert!(is_same_or_subdomain_fqdn(
        "www.example.com.",
        "example.com."
    ));
    assert!(is_same_or_subdomain_fqdn("example.com.", "example.com."));
    assert!(!is_same_or_subdomain_fqdn("aexample.com.", "example.com."));
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
