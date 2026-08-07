use super::*;
use crate::model::record::RecordType;

#[test]
fn record_values_equal_normalizes_name_like_values() {
    assert!(record_values_equal(
        "192.0.2.10",
        None,
        "192.0.2.10",
        None,
        &RecordType::A
    ));
    assert!(record_values_equal(
        "2001:0db8:0000:0000:0000:0000:0000:0001",
        None,
        "2001:db8::1",
        None,
        &RecordType::AAAA
    ));
    assert!(record_values_equal(
        "Target.Example.Net",
        None,
        "target.example.net.",
        None,
        &RecordType::CNAME
    ));
    assert!(record_values_equal(
        "Mail.Example.Com",
        Some(10),
        "mail.example.com.",
        Some(10),
        &RecordType::MX
    ));
    assert!(record_values_equal(
        "5 5060 Sip.Example.Com",
        Some(10),
        "5 5060 sip.example.com.",
        Some(10),
        &RecordType::SRV
    ));
    assert!(!record_values_equal(
        "Token=ABC",
        None,
        "token=abc",
        None,
        &RecordType::TXT
    ));
}

#[test]
fn record_values_equal_normalizes_soa_records() {
    assert!(record_values_equal(
        "NS1.Example.COM hostmaster.example.com 2024010101 7200 3600 1209600 3600",
        None,
        "ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 3600",
        None,
        &RecordType::SOA,
    ));
    assert!(!record_values_equal(
        "ns1.example.com hostmaster.example.com 2024010101 7200 3600 1209600 3600",
        None,
        "ns1.example.com hostmaster.example.com 2024010102 7200 3600 1209600 3600",
        None,
        &RecordType::SOA,
    ));
}
