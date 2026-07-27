use super::{
    NameError, email_to_soa_mailbox, soa_mailbox_to_email, split_presentation_labels, to_owner_fqdn,
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
fn email_to_soa_mailbox_escapes_local_part() {
    assert_eq!(
        email_to_soa_mailbox(r"host.master\ops@example.com").unwrap(),
        r"host\.master\\ops.example.com."
    );
    assert!(email_to_soa_mailbox("hostmaster.example.com").is_err());
    assert!(email_to_soa_mailbox("host@@example.com").is_err());
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
fn soa_mailbox_to_email_round_trips() {
    for email in [
        "admin@example.com",
        "first.last@example.com",
        "a.b.c@sub.example.com",
        "back\\slash@example.com",
    ] {
        let mailbox = email_to_soa_mailbox(email).expect("email should convert to mailbox");
        assert_eq!(
            soa_mailbox_to_email(&mailbox).expect("mailbox should convert back"),
            email,
            "round trip failed for mailbox '{mailbox}'"
        );
    }
}

#[test]
fn soa_mailbox_to_email_handles_plain_mailbox() {
    assert_eq!(
        soa_mailbox_to_email("hostmaster.example.com.").unwrap(),
        "hostmaster@example.com"
    );
    assert_eq!(
        soa_mailbox_to_email("hostmaster.example.com").unwrap(),
        "hostmaster@example.com"
    );
}

#[test]
fn soa_mailbox_to_email_rejects_invalid_input() {
    assert_eq!(
        soa_mailbox_to_email("no-separator").unwrap_err(),
        NameError::InvalidEmail
    );
    assert_eq!(
        soa_mailbox_to_email(".example.com").unwrap_err(),
        NameError::InvalidEmail
    );
    assert_eq!(
        soa_mailbox_to_email("dangling\\").unwrap_err(),
        NameError::DanglingEscape
    );
}
