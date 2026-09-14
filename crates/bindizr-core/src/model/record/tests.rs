use super::RecordType;
use crate::dns::record::TxtRecordValue;

/// Verify that `values_equal` normalizes name like values.
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

/// Verify that `encoded_value` produces one spelling per RDATA.
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
}

/// Verify that `encoded_value` keeps null MX and SRV root targets.
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

/// Verify that `encoded_value` rejects invalid values.
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

/// Verify that `encoded_value` round-trips TXT presentation form.
#[test]
fn encoded_value_round_trips_txt_presentation_form() {
    let encoded = RecordType::TXT.encoded_value("\"a\" \"b\"", None).unwrap();
    assert_eq!(
        RecordType::TXT.presentation_rdata(&encoded, None),
        "\"a\" \"b\""
    );
}

/// Verify that `display_value` adds trailing dot for name like values.
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

/// Verify that `display_value` keeps non name values unchanged.
#[test]
fn display_value_keeps_non_name_values_unchanged() {
    assert_eq!(RecordType::A.display_value("127.0.0.1"), "127.0.0.1");
    assert_eq!(RecordType::AAAA.display_value("2001:db8::1"), "2001:db8::1");
    assert_eq!(
        RecordType::TXT.display_value("v=spf1 include:example.net"),
        "v=spf1 include:example.net"
    );
}

/// Verify that `display_value` leaves wrong field count unchanged.
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

/// Hyphen-edge and non-LDH labels are not here: an rdata name takes the labels
/// an owner name does, so only what no presentation form spells back is left.
#[test]
fn validate_cname_ns_and_ptr_values_reject_invalid_domain_forms() {
    for record_type in [RecordType::CNAME, RecordType::NS, RecordType::PTR] {
        for value in [
            "",
            ".",
            "bad target.example.com",
            " leading.example.com",
            "trailing.example.com ",
            "bad..example.com",
        ] {
            assert!(
                record_type.validate_value(value, None).is_err(),
                "{record_type} value {value:?} should be rejected"
            );
        }
    }
}

/// Verify that validate MX value accepts a target with a field priority.
#[test]
fn validate_mx_value_accepts_a_target_with_a_field_priority() {
    assert!(
        RecordType::MX
            .validate_value("mail.example.com", Some(10))
            .is_ok()
    );
    // An omitted priority defaults to 10.
    assert!(
        RecordType::MX
            .validate_value("mail.example.com", None)
            .is_ok()
    );
    assert!(RecordType::MX.validate_value(".", Some(0)).is_ok());
}

/// Verify that validate MX value rejects invalid forms.
#[test]
fn validate_mx_value_rejects_invalid_forms() {
    for (value, priority) in [
        ("", None),
        // Priority belongs in the priority field, never inline in the value.
        ("10 mail.example.com", None),
        ("10 mail.example.com", Some(10)),
        ("mail.example.com extra", None),
        (".", None),
        (".", Some(10)),
        ("bad target.example.com", None),
        ("bad..example.com", None),
        ("mail.example.com", Some(-1)),
        ("mail.example.com", Some(65_536)),
    ] {
        assert!(
            RecordType::MX.validate_value(value, priority).is_err(),
            "MX value {value:?} with priority {priority:?} should be rejected"
        );
    }
}

/// Verify that validate SRV value accepts weight port target with a field priority.
#[test]
fn validate_srv_value_accepts_weight_port_target_with_a_field_priority() {
    assert!(
        RecordType::SRV
            .validate_value("5 5060 sip.example.com", Some(10))
            .is_ok()
    );
    // An omitted priority defaults to 10.
    assert!(
        RecordType::SRV
            .validate_value("5 5060 sip.example.com", None)
            .is_ok()
    );
    assert!(RecordType::SRV.validate_value("0 443 .", Some(0)).is_ok());
}

/// Verify that validate SRV value rejects invalid forms.
#[test]
fn validate_srv_value_rejects_invalid_forms() {
    for (value, priority) in [
        ("", None),
        ("5060 sip.example.com", None),
        // Priority belongs in the priority field, never inline in the value.
        ("10 5 5060 sip.example.com", None),
        ("10 5 5060 sip.example.com", Some(10)),
        ("5 5060 sip.example.com extra", None),
        ("not-a-weight 5060 sip.example.com", None),
        ("5 not-a-port sip.example.com", None),
        ("65536 5060 sip.example.com", None),
        ("5 65536 sip.example.com", None),
        ("5 5060 bad target.example.com", None),
        ("5 5060 bad..example.com", None),
        ("5 5060 sip.example.com", Some(-1)),
        ("5 5060 sip.example.com", Some(65_536)),
    ] {
        assert!(
            RecordType::SRV.validate_value(value, priority).is_err(),
            "SRV value {value:?} with priority {priority:?} should be rejected"
        );
    }
}

/// Verify that `validate_value` rejects priority on types without one.
#[test]
fn validate_value_rejects_priority_on_types_without_one() {
    let encoded_txt = TxtRecordValue::from_string("hello").to_presentation();
    for (record_type, value) in [
        (RecordType::A, "192.0.2.1"),
        (RecordType::AAAA, "2001:db8::1"),
        (RecordType::CNAME, "target.example.com"),
        (RecordType::TXT, encoded_txt.as_str()),
        (RecordType::NS, "ns1.example.com"),
        (RecordType::PTR, "host.example.com"),
    ] {
        assert!(
            record_type.validate_value(value, Some(10)).is_err(),
            "{record_type} should reject a priority"
        );
        assert!(record_type.validate_value(value, None).is_ok());
    }
}
