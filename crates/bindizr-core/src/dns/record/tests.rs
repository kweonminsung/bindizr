use super::{display_record_owner_name, display_record_value};
use crate::model::record::RecordType;

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

#[test]
fn display_record_value_adds_trailing_dot_for_name_like_values() {
    assert_eq!(
        display_record_value("ns.test.example.com", &RecordType::NS),
        "ns.test.example.com."
    );
    assert_eq!(
        display_record_value("Target.Example.Net", &RecordType::CNAME),
        "target.example.net."
    );
    assert_eq!(
        display_record_value("10 mail.example.com", &RecordType::MX),
        "10 mail.example.com."
    );
    assert_eq!(
        display_record_value("10 5 5060 sip.example.com", &RecordType::SRV),
        "10 5 5060 sip.example.com."
    );
    assert_eq!(
        display_record_value("host.example.com", &RecordType::PTR),
        "host.example.com."
    );
}

#[test]
fn display_record_value_keeps_non_name_values_unchanged() {
    assert_eq!(
        display_record_value("127.0.0.1", &RecordType::A),
        "127.0.0.1"
    );
    assert_eq!(
        display_record_value("2001:db8::1", &RecordType::AAAA),
        "2001:db8::1"
    );
    assert_eq!(
        display_record_value("v=spf1 include:example.net", &RecordType::TXT),
        "v=spf1 include:example.net"
    );
}

#[test]
fn display_record_value_keeps_split_priority_forms() {
    // Priority can live in the separate column, so the stored value omits it.
    assert_eq!(
        display_record_value("mail.example.com", &RecordType::MX),
        "mail.example.com."
    );
    assert_eq!(
        display_record_value("5 5060 sip.example.com", &RecordType::SRV),
        "5 5060 sip.example.com."
    );
}

#[test]
fn display_record_value_leaves_wrong_field_count_unchanged() {
    // Legacy rows whose field count cannot match any valid MX/SRV form must not be
    // rewritten into a fake hostname (e.g. a trailing numeric field gaining a dot).
    for value in ["", "10 mail.example.com extra"] {
        assert_eq!(
            display_record_value(value, &RecordType::MX),
            value,
            "malformed MX value {value:?} should be returned unchanged"
        );
    }

    for value in ["", "10 5", "10 5 5060 sip.example.com extra"] {
        assert_eq!(
            display_record_value(value, &RecordType::SRV),
            value,
            "malformed SRV value {value:?} should be returned unchanged"
        );
    }
}
