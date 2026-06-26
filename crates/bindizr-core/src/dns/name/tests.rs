use super::{email_to_soa_mailbox, is_in_bailiwick, split_presentation_labels, to_relative_domain};

#[test]
fn is_in_bailiwick_accepts_apex_and_subdomain() {
    assert!(is_in_bailiwick("example.com.", "example.com."));
    assert!(is_in_bailiwick("ns.example.com.", "example.com."));
}

#[test]
fn is_in_bailiwick_rejects_sibling_suffix_match() {
    assert!(!is_in_bailiwick("notexample.com.", "example.com."));
    assert!(!is_in_bailiwick("ns.notexample.com.", "example.com."));
}

#[test]
fn to_relative_domain_converts_only_zone_apex_and_subdomains() {
    assert_eq!(to_relative_domain("example.com.", "example.com."), "@");
    assert_eq!(to_relative_domain("ns.example.com.", "example.com."), "ns");
    assert_eq!(
        to_relative_domain("notexample.com.", "example.com."),
        "notexample.com"
    );
}

#[test]
fn split_presentation_labels_preserves_escaped_dots_and_rejects_dangling_escape() {
    assert_eq!(
        split_presentation_labels(r"host\.name.example.com").unwrap(),
        vec!["host.name", "example", "com"]
    );
    assert!(split_presentation_labels(r"bad.example.com\").is_err());
}

#[test]
fn email_to_soa_mailbox_escapes_local_part() {
    assert_eq!(
        email_to_soa_mailbox(r"host.master\ops@example.com").unwrap(),
        r"host\.master\\ops.example.com."
    );
    assert!(email_to_soa_mailbox("hostmaster.example.com").is_err());
    assert!(email_to_soa_mailbox("host@@example.com").is_err());
}
