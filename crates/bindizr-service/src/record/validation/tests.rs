use chrono::Utc;

use super::{
    normalize_record_owner_name, record_values_equal, validate_delete_constraints,
    validate_record_add_constraints, validate_record_value,
};
use crate::model::{
    record::{Record, RecordType},
    zone::Zone,
};

#[test]
fn normalize_record_owner_name_accepts_relative_and_in_bailiwick_absolute_names() {
    let zone = "test.example.com";

    let apex = normalize_record_owner_name("@", zone).unwrap();
    assert_eq!(apex.stored_name, "@");

    let relative = normalize_record_owner_name("a1", zone).unwrap();
    assert_eq!(relative.stored_name, "a1");

    let relative_with_zone_suffix =
        normalize_record_owner_name("A1.Test.Example.Com", zone).unwrap();
    assert_eq!(relative_with_zone_suffix.stored_name, "a1");

    let absolute = normalize_record_owner_name("A1.Test.Example.Com.", zone).unwrap();
    assert_eq!(absolute.stored_name, "a1");
}

#[test]
fn normalize_record_owner_name_rejects_out_of_bailiwick_absolute_names() {
    let zone = "test.example.com";

    for name in [
        "a1.",
        "example.com.",
        "a1.example.com.",
        "other.com.",
        "a1.other.com.",
        "badtest.example.com.",
    ] {
        assert!(
            normalize_record_owner_name(name, zone).is_err(),
            "{name} should be rejected"
        );
    }
}

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
        "10 mail.example.com",
        None,
        "10 mail.example.com.",
        None,
        &RecordType::MX
    ));
    assert!(record_values_equal(
        "mail.example.com",
        Some(10),
        "010 mail.example.com.",
        None,
        &RecordType::MX
    ));
    assert!(record_values_equal(
        "10 5 5060 sip.example.com",
        None,
        "10 5 5060 sip.example.com.",
        None,
        &RecordType::SRV
    ));
    assert!(record_values_equal(
        "5 5060 sip.example.com",
        Some(10),
        "010 005 5060 sip.example.com.",
        None,
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
fn validate_cname_value_accepts_underscore_labels() {
    assert!(
        validate_record_value(
            &RecordType::CNAME,
            "_acme-challenge.validation.example.",
            None
        )
        .is_ok()
    );
}

#[test]
fn validate_cname_value_rejects_invalid_domain_forms() {
    for value in [
        "",
        ".",
        "bad target.example.com",
        "bad..example.com",
        "-bad.example.com",
        "bad-.example.com",
    ] {
        assert!(
            validate_record_value(&RecordType::CNAME, value, None).is_err(),
            "{value:?} should be rejected"
        );
    }
}

#[test]
fn validate_ns_and_ptr_values_reject_invalid_domain_forms() {
    for record_type in [RecordType::NS, RecordType::PTR] {
        for value in [
            "",
            ".",
            "bad target.example.com",
            " leading.example.com",
            "trailing.example.com ",
            "bad..example.com",
            "-bad.example.com",
            "bad-.example.com",
        ] {
            assert!(
                validate_record_value(&record_type, value, None).is_err(),
                "{record_type} value {value:?} should be rejected"
            );
        }
    }
}

#[test]
fn validate_mx_value_accepts_full_and_split_priority_forms() {
    assert!(validate_record_value(&RecordType::MX, "10 mail.example.com", None).is_ok());
    assert!(validate_record_value(&RecordType::MX, "mail.example.com", Some(10)).is_ok());
    assert!(validate_record_value(&RecordType::MX, "mail.example.com", None).is_ok());
    assert!(validate_record_value(&RecordType::MX, "0 .", None).is_ok());
    assert!(validate_record_value(&RecordType::MX, ".", Some(0)).is_ok());
}

#[test]
fn validate_mx_value_rejects_invalid_forms() {
    for (value, priority) in [
        ("", None),
        ("10 mail.example.com extra", None),
        ("not-a-priority mail.example.com", None),
        ("65536 mail.example.com", None),
        ("10 .", None),
        (".", None),
        (".", Some(10)),
        ("10 bad target.example.com", None),
        ("10 bad..example.com", None),
        ("10 mail.example.com", Some(10)),
        ("mail.example.com", Some(-1)),
        ("mail.example.com", Some(65_536)),
    ] {
        assert!(
            validate_record_value(&RecordType::MX, value, priority).is_err(),
            "MX value {value:?} with priority {priority:?} should be rejected"
        );
    }
}

#[test]
fn validate_srv_value_accepts_full_and_split_priority_forms() {
    assert!(validate_record_value(&RecordType::SRV, "10 5 5060 sip.example.com", None).is_ok());
    assert!(validate_record_value(&RecordType::SRV, "5 5060 sip.example.com", Some(10)).is_ok());
    assert!(validate_record_value(&RecordType::SRV, "5 5060 sip.example.com", None).is_ok());
    assert!(validate_record_value(&RecordType::SRV, "0 0 443 .", None).is_ok());
    assert!(validate_record_value(&RecordType::SRV, "0 443 .", Some(0)).is_ok());
}

#[test]
fn validate_srv_value_rejects_invalid_forms() {
    for (value, priority) in [
        ("", None),
        ("10 5", None),
        ("10 5 5060 sip.example.com extra", None),
        ("not-a-priority 5 5060 sip.example.com", None),
        ("10 not-a-weight 5060 sip.example.com", None),
        ("10 5 not-a-port sip.example.com", None),
        ("65536 5 5060 sip.example.com", None),
        ("10 65536 5060 sip.example.com", None),
        ("10 5 65536 sip.example.com", None),
        ("10 5 5060 bad target.example.com", None),
        ("10 5 5060 bad..example.com", None),
        ("10 5 5060 sip.example.com", Some(10)),
        ("5 5060 sip.example.com", Some(-1)),
        ("5 5060 sip.example.com", Some(65_536)),
    ] {
        assert!(
            validate_record_value(&RecordType::SRV, value, priority).is_err(),
            "SRV value {value:?} with priority {priority:?} should be rejected"
        );
    }
}

#[test]
fn validate_soa_value_accepts_well_formed_records() {
    assert!(
        validate_record_value(
            &RecordType::SOA,
            "ns1.example.com hostmaster.example.com 2024010101 7200 3600 1209600 3600",
            None,
        )
        .is_ok()
    );
    assert!(
        validate_record_value(
            &RecordType::SOA,
            "ns1.example.com. hostmaster.example.com. 0 0 0 0 0",
            None,
        )
        .is_ok()
    );
}

#[test]
fn validate_soa_value_rejects_invalid_forms() {
    for value in [
        "",
        "ns1.example.com hostmaster.example.com",
        "ns1.example.com hostmaster.example.com 2024010101 7200 3600 1209600",
        "ns1.example.com hostmaster.example.com 2024010101 7200 3600 1209600 3600 extra",
        "ns1.example.com hostmaster.example.com serial 7200 3600 1209600 3600",
        "ns1.example.com hostmaster.example.com 2024010101 7200 3600 1209600 -1",
        "ns1.example.com hostmaster.example.com 2024010101 7200 3600 1209600 4294967296",
        "bad..example.com hostmaster.example.com 2024010101 7200 3600 1209600 3600",
        "ns1.example.com bad..example.com 2024010101 7200 3600 1209600 3600",
        ". . 2024010101 7200 3600 1209600 3600",
    ] {
        assert!(
            validate_record_value(&RecordType::SOA, value, None).is_err(),
            "SOA value {value:?} should be rejected"
        );
    }
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

#[test]
fn validate_record_add_constraints_enforces_cname_and_ns_owner_rules() {
    let zone = test_zone();

    let cname_at_apex = validate_record_add_constraints(
        &zone,
        &[],
        "@",
        &RecordType::CNAME,
        "target.example.com",
        None,
        None,
    );
    assert!(cname_at_apex.is_err());

    let ns_below_apex = validate_record_add_constraints(
        &zone,
        &[],
        "child",
        &RecordType::NS,
        "ns.example.com",
        None,
        None,
    );
    assert!(ns_below_apex.is_err());

    let existing_a = test_record(1, "www", RecordType::A, "192.0.2.10", None);
    let cname_conflict = validate_record_add_constraints(
        &zone,
        &[existing_a],
        "www",
        &RecordType::CNAME,
        "target.example.com",
        None,
        None,
    );
    assert!(cname_conflict.is_err());
}

#[test]
fn validate_record_add_constraints_rejects_wire_equivalent_mx_and_srv_duplicates() {
    let zone = test_zone();

    let existing_mx = test_record(1, "@", RecordType::MX, "mail.example.com", Some(10));
    let duplicate_mx = validate_record_add_constraints(
        &zone,
        &[existing_mx],
        "@",
        &RecordType::MX,
        "10 mail.example.com",
        Some(10),
        None,
    );
    assert!(duplicate_mx.is_err());

    let existing_srv = test_record(
        2,
        "_sip._tcp",
        RecordType::SRV,
        "5 5060 sip.example.com",
        Some(10),
    );
    let duplicate_srv = validate_record_add_constraints(
        &zone,
        &[existing_srv],
        "_sip._tcp",
        &RecordType::SRV,
        "10 5 5060 sip.example.com",
        Some(10),
        None,
    );
    assert!(duplicate_srv.is_err());
}

#[test]
fn validate_record_add_constraints_rejects_null_mx_with_other_mx_records() {
    let zone = test_zone();

    let existing_mx = test_record(1, "@", RecordType::MX, "mail.example.com", Some(10));
    let null_mx_with_existing_mx = validate_record_add_constraints(
        &zone,
        &[existing_mx],
        "@",
        &RecordType::MX,
        "0 .",
        None,
        None,
    );
    assert!(null_mx_with_existing_mx.is_err());

    let existing_null_mx = test_record(2, "@", RecordType::MX, ".", Some(0));
    let mx_with_existing_null_mx = validate_record_add_constraints(
        &zone,
        &[existing_null_mx],
        "@",
        &RecordType::MX,
        "mail.example.com",
        Some(10),
        None,
    );
    assert!(mx_with_existing_null_mx.is_err());
}

#[test]
fn validate_delete_constraints_protects_soa_and_primary_ns() {
    let zone = test_zone();

    let soa = test_record(
        1,
        "@",
        RecordType::SOA,
        "ns1.example.com hostmaster.example.com",
        None,
    );
    assert!(validate_delete_constraints(&zone, &[soa]).is_err());

    let primary_ns = test_record(2, "@", RecordType::NS, "ns1.example.com.", None);
    assert!(validate_delete_constraints(&zone, &[primary_ns]).is_err());

    let secondary_ns = test_record(3, "@", RecordType::NS, "ns2.example.com.", None);
    assert!(validate_delete_constraints(&zone, &[secondary_ns]).is_ok());
}

fn test_zone() -> Zone {
    Zone {
        id: 1,
        name: "example.com".to_string(),
        primary_ns: "ns1.example.com".to_string(),
        admin_email: "hostmaster@example.com".to_string(),
        ttl: 3600,
        serial: 2023010101,
        refresh: 7200,
        retry: 3600,
        expire: 604800,
        minimum_ttl: 86400,
        created_at: Utc::now(),
    }
}

fn test_record(
    id: i32,
    name: &str,
    record_type: RecordType,
    value: &str,
    priority: Option<i32>,
) -> Record {
    Record {
        id,
        name: name.to_string(),
        record_type,
        value: value.to_string(),
        ttl: Some(3600),
        priority,
        zone_id: 1,
        created_at: Utc::now(),
    }
}
