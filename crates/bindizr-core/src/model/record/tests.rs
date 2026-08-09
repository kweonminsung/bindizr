use super::RecordType;
use crate::dns::record::TxtRdata;

#[test]
fn values_equal_normalizes_name_like_values() {
    assert!(RecordType::A.values_equal("192.0.2.10", None, "192.0.2.10", None));
    assert!(RecordType::AAAA.values_equal(
        "2001:0db8:0000:0000:0000:0000:0000:0001",
        None,
        "2001:db8::1",
        None
    ));
    assert!(RecordType::CNAME.values_equal(
        "Target.Example.Net",
        None,
        "target.example.net.",
        None
    ));
    assert!(RecordType::MX.values_equal(
        "Mail.Example.Com",
        Some(10),
        "mail.example.com.",
        Some(10)
    ));
    assert!(RecordType::SRV.values_equal(
        "5 5060 Sip.Example.Com",
        Some(10),
        "5 5060 sip.example.com.",
        Some(10)
    ));
    assert!(!RecordType::TXT.values_equal("Token=ABC", None, "token=abc", None));
}

#[test]
fn values_equal_normalizes_soa_records() {
    assert!(RecordType::SOA.values_equal(
        "NS1.Example.COM hostmaster.example.com 2024010101 7200 3600 1209600 3600",
        None,
        "ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 3600",
        None
    ));
    assert!(!RecordType::SOA.values_equal(
        "ns1.example.com hostmaster.example.com 2024010101 7200 3600 1209600 3600",
        None,
        "ns1.example.com hostmaster.example.com 2024010102 7200 3600 1209600 3600",
        None
    ));
}

#[test]
fn encoded_value_produces_one_spelling_per_rdata() {
    assert_eq!(
        RecordType::AAAA
            .encoded_value("2001:0DB8:0000:0000:0000:0000:0000:0001", None)
            .as_deref(),
        Ok("2001:db8::1")
    );
    assert_eq!(
        RecordType::CNAME
            .encoded_value("Target.Example.Net", None)
            .as_deref(),
        Ok("target.example.net.")
    );
    assert_eq!(
        RecordType::MX
            .encoded_value("Mail.Example.Com", Some(10))
            .as_deref(),
        Ok("mail.example.com.")
    );
    assert_eq!(
        RecordType::SRV
            .encoded_value("5 5060 Sip.Example.Com.", Some(10))
            .as_deref(),
        Ok("5 5060 sip.example.com.")
    );
    assert_eq!(
        RecordType::SOA
            .encoded_value(
                "NS1.Example.COM hostmaster.example.com 1 7200 3600 1209600 3600",
                None
            )
            .as_deref(),
        Ok("ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600")
    );
}

#[test]
fn encoded_value_keeps_null_mx_and_srv_root_targets() {
    assert_eq!(
        RecordType::MX.encoded_value(".", Some(0)).as_deref(),
        Ok(".")
    );
    assert_eq!(
        RecordType::SRV.encoded_value("0 443 .", Some(0)).as_deref(),
        Ok("0 443 .")
    );
}

#[test]
fn encoded_value_rejects_invalid_values() {
    assert!(RecordType::A.encoded_value("not-an-ip", None).is_err());
    assert!(
        RecordType::CNAME
            .encoded_value("bad..example.com", None)
            .is_err()
    );
    assert!(
        RecordType::MX
            .encoded_value("10 mail.example.com", None)
            .is_err()
    );
    assert!(RecordType::MX.encoded_value(".", Some(10)).is_err());
    assert!(RecordType::TXT.encoded_value("", None).is_err());
}

#[test]
fn encoded_value_round_trips_txt_presentation_form() {
    let encoded = RecordType::TXT.encoded_value("\"a\" \"b\"", None).unwrap();
    assert_eq!(
        RecordType::TXT.presentation_rdata(&encoded, None),
        "\"a\" \"b\""
    );
}

#[test]
fn presentation_rdata_txt_escapes_special_characters() {
    let ascii = TxtRdata::from_string("v=spf1 \"x\\y\"").into_encoded();
    assert_eq!(
        RecordType::TXT.presentation_rdata(&ascii, None),
        "\"v=spf1 \\\"x\\\\y\\\"\""
    );

    // Control bytes are escaped as \DDD per RFC 1035, Section 5.1.
    let control = TxtRdata::from_string("a\u{1}b").into_encoded();
    assert_eq!(
        RecordType::TXT.presentation_rdata(&control, None),
        "\"a\\001b\""
    );
}

#[test]
fn display_value_adds_trailing_dot_for_name_like_values() {
    assert_eq!(
        RecordType::NS.display_value("ns.test.example.com"),
        "ns.test.example.com."
    );
    assert_eq!(
        RecordType::CNAME.display_value("Target.Example.Net"),
        "target.example.net."
    );
    assert_eq!(
        RecordType::MX.display_value("mail.example.com"),
        "mail.example.com."
    );
    assert_eq!(
        RecordType::SRV.display_value("5 5060 sip.example.com"),
        "5 5060 sip.example.com."
    );
    assert_eq!(
        RecordType::PTR.display_value("host.example.com"),
        "host.example.com."
    );
}

#[test]
fn display_value_keeps_non_name_values_unchanged() {
    assert_eq!(RecordType::A.display_value("127.0.0.1"), "127.0.0.1");
    assert_eq!(RecordType::AAAA.display_value("2001:db8::1"), "2001:db8::1");
    assert_eq!(
        RecordType::TXT.display_value("v=spf1 include:example.net"),
        "v=spf1 include:example.net"
    );
}

#[test]
fn display_value_leaves_wrong_field_count_unchanged() {
    // Values whose field count cannot match any valid MX/SRV form must not be
    // rewritten into a fake hostname (e.g. a trailing numeric field gaining a dot).
    for value in ["", "10 mail.example.com", "10 mail.example.com extra"] {
        assert_eq!(
            RecordType::MX.display_value(value),
            value,
            "malformed MX value {value:?} should be returned unchanged"
        );
    }

    for value in ["", "10 5", "10 5 5060 sip.example.com"] {
        assert_eq!(
            RecordType::SRV.display_value(value),
            value,
            "malformed SRV value {value:?} should be returned unchanged"
        );
    }
}
