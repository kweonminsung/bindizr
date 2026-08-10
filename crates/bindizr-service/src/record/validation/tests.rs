use bindizr_core::dns::name::OwnerName;
use chrono::Utc;

use super::{
    normalize_record_owner_name, validate_delete_constraints,
    validate_record_add_constraints_normalized, validate_record_value,
};
use crate::{
    error::{ErrorCode, ServiceError},
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
};

/// TTL of every [`test_record`], so adds under test share their RRset's TTL
/// instead of tripping the RRset TTL rule.
const RRSET_TTL: i32 = 3600;

#[test]
fn normalize_record_owner_name_maps_parse_failures_to_record_name_errors() {
    // Core owns the parsing; this layer owns the code and the message.
    let zone = "test.example.com";

    let outside = normalize_record_owner_name("a1.other.com.", zone).unwrap_err();
    assert_eq!(outside.code, ErrorCode::InvalidRecordName);
    assert!(outside.message.contains("a1.other.com."));
    assert!(outside.message.contains(zone));

    let empty = normalize_record_owner_name("  ", zone).unwrap_err();
    assert_eq!(empty.code, ErrorCode::InvalidRecordName);
    assert!(empty.message.starts_with("record name "));
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
fn validate_cname_ns_and_ptr_values_reject_invalid_domain_forms() {
    for record_type in [RecordType::CNAME, RecordType::NS, RecordType::PTR] {
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
fn validate_mx_value_accepts_a_target_with_a_field_priority() {
    assert!(validate_record_value(&RecordType::MX, "mail.example.com", Some(10)).is_ok());
    // An omitted priority defaults to 10.
    assert!(validate_record_value(&RecordType::MX, "mail.example.com", None).is_ok());
    assert!(validate_record_value(&RecordType::MX, ".", Some(0)).is_ok());
}

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
            validate_record_value(&RecordType::MX, value, priority).is_err(),
            "MX value {value:?} with priority {priority:?} should be rejected"
        );
    }
}

#[test]
fn validate_srv_value_accepts_weight_port_target_with_a_field_priority() {
    assert!(validate_record_value(&RecordType::SRV, "5 5060 sip.example.com", Some(10)).is_ok());
    // An omitted priority defaults to 10.
    assert!(validate_record_value(&RecordType::SRV, "5 5060 sip.example.com", None).is_ok());
    assert!(validate_record_value(&RecordType::SRV, "0 443 .", Some(0)).is_ok());
}

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

/// Validate an add whose owner name is already in stored form.
fn validate_add(
    zone_records: &[Record],
    stored_name: &str,
    record_type: &RecordType,
    value: &str,
    ttl: i32,
    priority: Option<i32>,
) -> Result<(), ServiceError> {
    validate_record_add_constraints_normalized(
        zone_records,
        &OwnerName::from_row(stored_name),
        record_type,
        value,
        ttl,
        priority,
        None,
    )
}

#[test]
fn add_rejects_cname_at_apex_and_ns_below_apex() {
    let cname_at_apex = validate_add(
        &[],
        "",
        &RecordType::CNAME,
        "target.example.com",
        RRSET_TTL,
        None,
    );
    assert_eq!(
        cname_at_apex.unwrap_err().code,
        ErrorCode::InvalidRecordName
    );

    let ns_below_apex = validate_add(
        &[],
        "child",
        &RecordType::NS,
        "ns.example.com",
        RRSET_TTL,
        None,
    );
    assert_eq!(
        ns_below_apex.unwrap_err().code,
        ErrorCode::InvalidRecordName
    );

    let existing_a = test_record(1, "www", RecordType::A, "192.0.2.10", None);
    let cname_conflict = validate_add(
        &[existing_a],
        "www",
        &RecordType::CNAME,
        "target.example.com",
        RRSET_TTL,
        None,
    );
    assert_eq!(cname_conflict.unwrap_err().code, ErrorCode::RecordConflict);
}

#[test]
fn add_rejects_wire_equivalent_mx_and_srv_duplicates() {
    // Case and trailing-dot differences canonicalize equal, so the add is a duplicate.
    let existing_mx = test_record(1, "", RecordType::MX, "mail.example.com", Some(10));
    let duplicate_mx = validate_add(
        &[existing_mx],
        "",
        &RecordType::MX,
        "Mail.Example.Com.",
        RRSET_TTL,
        Some(10),
    );
    assert_eq!(duplicate_mx.unwrap_err().code, ErrorCode::RecordConflict);

    let existing_srv = test_record(
        2,
        "_sip._tcp",
        RecordType::SRV,
        "5 5060 sip.example.com",
        Some(10),
    );
    let duplicate_srv = validate_add(
        &[existing_srv],
        "_sip._tcp",
        &RecordType::SRV,
        "5 5060 Sip.Example.Com.",
        RRSET_TTL,
        Some(10),
    );
    assert_eq!(duplicate_srv.unwrap_err().code, ErrorCode::RecordConflict);
}

#[test]
fn add_treats_an_omitted_mx_priority_as_the_default() {
    // A stored MX with no priority and an add carrying the default 10 are the
    // same rdata, so nsupdate can no-op the add instead of refusing it.
    let existing_mx = test_record(1, "", RecordType::MX, "mail.example.com.", None);
    let duplicate_mx = validate_add(
        &[existing_mx],
        "",
        &RecordType::MX,
        "mail.example.com.",
        RRSET_TTL,
        Some(10),
    );
    assert_eq!(duplicate_mx.unwrap_err().code, ErrorCode::RecordConflict);
}

#[test]
fn add_rejects_null_mx_alongside_other_mx_records() {
    let existing_mx = test_record(1, "", RecordType::MX, "mail.example.com", Some(10));
    let null_mx_with_existing_mx =
        validate_add(&[existing_mx], "", &RecordType::MX, ".", RRSET_TTL, Some(0));
    assert_eq!(
        null_mx_with_existing_mx.unwrap_err().code,
        ErrorCode::RecordConflict
    );

    let existing_null_mx = test_record(2, "", RecordType::MX, ".", Some(0));
    let mx_with_existing_null_mx = validate_add(
        &[existing_null_mx],
        "",
        &RecordType::MX,
        "mail.example.com",
        RRSET_TTL,
        Some(10),
    );
    assert_eq!(
        mx_with_existing_null_mx.unwrap_err().code,
        ErrorCode::RecordConflict
    );
}

#[test]
fn add_enforces_one_ttl_per_rrset() {
    let existing_a = test_record(1, "www", RecordType::A, "192.0.2.10", None);

    let differing_ttl = validate_add(
        std::slice::from_ref(&existing_a),
        "www",
        &RecordType::A,
        "192.0.2.11",
        600,
        None,
    );
    assert_eq!(differing_ttl.unwrap_err().code, ErrorCode::RecordConflict);

    let matching_ttl = validate_add(
        std::slice::from_ref(&existing_a),
        "www",
        &RecordType::A,
        "192.0.2.11",
        RRSET_TTL,
        None,
    );
    assert!(matching_ttl.is_ok());

    // A different type at the same owner name is a different RRset.
    let other_rrset = validate_add(
        std::slice::from_ref(&existing_a),
        "www",
        &RecordType::TXT,
        "hello",
        600,
        None,
    );
    assert!(other_rrset.is_ok());
}

#[test]
fn validate_record_value_rejects_priority_on_types_without_one() {
    for (record_type, value) in [
        (RecordType::A, "192.0.2.1"),
        (RecordType::AAAA, "2001:db8::1"),
        (RecordType::CNAME, "target.example.com"),
        (RecordType::TXT, "hello"),
        (RecordType::NS, "ns1.example.com"),
        (RecordType::PTR, "host.example.com"),
    ] {
        assert!(
            validate_record_value(&record_type, value, Some(10)).is_err(),
            "{record_type} should reject a priority"
        );
        assert!(validate_record_value(&record_type, value, None).is_ok());
    }
}

#[test]
fn validate_delete_constraints_protects_soa_and_primary_ns() {
    let zone = test_zone();

    let soa = test_record(
        1,
        "",
        RecordType::SOA,
        "ns1.example.com hostmaster.example.com",
        None,
    );
    assert!(validate_delete_constraints(&zone, &[soa]).is_err());

    let primary_ns = test_record(2, "", RecordType::NS, "ns1.example.com.", None);
    assert!(validate_delete_constraints(&zone, &[primary_ns]).is_err());

    let secondary_ns = test_record(3, "", RecordType::NS, "ns2.example.com.", None);
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
        ttl: RRSET_TTL,
        priority,
        zone_id: 1,
        created_at: Utc::now(),
    }
}
