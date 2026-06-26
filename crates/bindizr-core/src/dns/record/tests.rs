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
