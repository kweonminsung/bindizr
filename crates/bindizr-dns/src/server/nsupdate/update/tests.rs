use domain::base::iana::{Class, Rtype};

use super::{
    UpdateError, absolute_to_relative, normalize_owner_name, record_value_matches,
    rr_to_record_value, validate_delete_update_shape,
};
use crate::{model::record::RecordType, server::nsupdate::parser::UpdateRecord};

#[test]
fn absolute_to_relative_accepts_apex() {
    let relative = absolute_to_relative("example.com.", "example.com.").unwrap();
    assert_eq!(relative, "@");
}

#[test]
fn absolute_to_relative_accepts_subdomain_at_label_boundary() {
    let relative = absolute_to_relative("www.example.com.", "example.com.").unwrap();
    assert_eq!(relative, "www");
}

#[test]
fn absolute_to_relative_rejects_partial_suffix_match() {
    let err = absolute_to_relative("aexample.com.", "example.com.").unwrap_err();
    assert!(matches!(err, UpdateError::NotZone(_)));
}

#[test]
fn normalize_owner_name_rejects_out_of_zone_suffix_matches() {
    assert!(normalize_owner_name("www.example.com.", "example.com.").is_ok());

    for owner in ["badexample.com.", "www.badexample.com.", "."] {
        let err = normalize_owner_name(owner, "example.com.").unwrap_err();
        assert!(matches!(err, UpdateError::NotZone(_)));
    }
}

// Delete-update wire shapes are fixed by RFC 2136: delete-RRset is CLASS ANY +
// TTL 0 + empty RDATA (Section 2.5.2), delete-specific-RR is CLASS NONE + TTL 0 +
// RDATA present (Section 2.5.4); every other combination must be refused.
#[test]
fn validate_delete_update_shape_accepts_any_class_rrset_delete() {
    let update = update_record(Rtype::A, Class::ANY, 0, Vec::new());

    validate_delete_update_shape(&update, true).unwrap();
}

#[test]
fn validate_delete_update_shape_accepts_none_class_exact_delete() {
    let update = update_record(Rtype::A, Class::NONE, 0, vec![192, 0, 2, 1]);

    validate_delete_update_shape(&update, false).unwrap();
}

#[test]
fn validate_delete_update_shape_rejects_delete_with_nonzero_ttl() {
    let update = update_record(Rtype::A, Class::ANY, 60, Vec::new());
    let err = validate_delete_update_shape(&update, true).unwrap_err();

    assert!(matches!(err, UpdateError::Refused(_)));
}

#[test]
fn validate_delete_update_shape_rejects_any_class_delete_with_rdata() {
    let update = update_record(Rtype::A, Class::ANY, 0, vec![192, 0, 2, 1]);
    let err = validate_delete_update_shape(&update, true).unwrap_err();

    assert!(matches!(err, UpdateError::Refused(_)));
}

#[test]
fn validate_delete_update_shape_rejects_none_class_delete_without_rdata() {
    let update = update_record(Rtype::A, Class::NONE, 0, Vec::new());
    let err = validate_delete_update_shape(&update, false).unwrap_err();

    assert!(matches!(err, UpdateError::Refused(_)));
}

#[test]
fn validate_delete_update_shape_rejects_none_class_delete_with_type_any() {
    let update = update_record(Rtype::ANY, Class::NONE, 0, vec![192, 0, 2, 1]);
    let err = validate_delete_update_shape(&update, false).unwrap_err();

    assert!(matches!(err, UpdateError::Refused(_)));
}

#[test]
fn record_value_matches_preserves_txt_case() {
    assert!(record_value_matches(&RecordType::TXT, "Hello", "Hello"));
    assert!(!record_value_matches(&RecordType::TXT, "Hello", "hello"));
}

#[test]
fn rr_to_record_value_preserves_txt_character_string_boundaries() {
    let first = UpdateRecord {
        name: "txt.example.com.".to_string(),
        rr_type: Rtype::TXT,
        class: Class::IN,
        ttl: 300,
        rdata: vec![2, b'a', b'b', 1, b'c'],
        rdata_start: 0,
    };
    let second = UpdateRecord {
        name: "txt.example.com.".to_string(),
        rr_type: Rtype::TXT,
        class: Class::IN,
        ttl: 300,
        rdata: vec![1, b'a', 2, b'b', b'c'],
        rdata_start: 0,
    };

    let (_, first_value, _) = rr_to_record_value(&first, &first.rdata).unwrap();
    let (_, second_value, _) = rr_to_record_value(&second, &second.rdata).unwrap();

    assert_ne!(first_value, second_value);
    assert!(record_value_matches(
        &RecordType::TXT,
        &first_value,
        &first_value
    ));
    assert!(!record_value_matches(
        &RecordType::TXT,
        &first_value,
        &second_value
    ));
}

#[test]
fn rr_to_record_value_follows_compression_pointer_in_name_rdata() {
    let mut message = vec![
        3, b'w', b'w', b'w', 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ];
    let rdata_start = message.len();
    let pointer = [0xC0, 5]; // Points at the "example.com." bytes above
    message.extend_from_slice(&pointer);

    let update = UpdateRecord {
        name: "www.example.com.".to_string(),
        rr_type: Rtype::CNAME,
        class: Class::IN,
        ttl: 300,
        rdata: pointer.to_vec(),
        rdata_start,
    };

    let (record_type, value, priority) = rr_to_record_value(&update, &message).unwrap();
    assert_eq!(record_type, RecordType::CNAME);
    assert_eq!(value, "example.com.");
    assert_eq!(priority, None);
}

#[test]
fn rr_to_record_value_rejects_non_backward_compression_pointers() {
    let forward = [
        0xC0, 0x02, // Pointer to the root label after this pointer
        0x00,
    ];
    let self_referential = [
        0xC0, 0x00, // Pointer to itself
    ];

    for message in [&forward[..], &self_referential[..]] {
        let update = update_record(Rtype::CNAME, Class::IN, 300, message[..2].to_vec());
        let err = rr_to_record_value(&update, message).unwrap_err();
        assert!(matches!(err, UpdateError::Refused(_)));
    }
}

#[test]
fn rr_to_record_value_rejects_name_rdata_with_trailing_bytes() {
    let message = [1, b'a', 0, 0];
    let update = update_record(Rtype::CNAME, Class::IN, 300, message.to_vec());
    let err = rr_to_record_value(&update, &message).unwrap_err();
    assert!(matches!(err, UpdateError::Refused(_)));
}

// TXT RDATA is one or more character-strings (RFC 1035, Section 3.3.14); an empty
// value previously slipped through and stored an undecodable record.
#[test]
fn rr_to_record_value_rejects_empty_txt_rdata() {
    let update = update_record(Rtype::TXT, Class::IN, 300, Vec::new());
    let err = rr_to_record_value(&update, &[]).unwrap_err();
    assert!(matches!(err, UpdateError::Refused(_)));
}

#[test]
fn rr_to_record_value_rejects_non_utf8_txt_character_strings() {
    let update = update_record(Rtype::TXT, Class::IN, 300, vec![1, 0xFF]);
    let err = rr_to_record_value(&update, &update.rdata).unwrap_err();
    assert!(matches!(err, UpdateError::Refused(_)));
}

#[test]
fn record_value_matches_ignores_case_for_name_like_values() {
    assert!(record_value_matches(
        &RecordType::NS,
        "Ns1.Example.Com.",
        "ns1.example.com."
    ));
    assert!(record_value_matches(
        &RecordType::MX,
        "Mail.Example.Com.",
        "mail.example.com."
    ));
}

#[test]
fn record_value_matches_normalizes_like_wire_rdata_comparison() {
    // A wire-derived delete names the same rdata regardless of how the stored
    // value spelled the address or whether it carried the trailing dot.
    assert!(record_value_matches(
        &RecordType::AAAA,
        "0:0:0:0:0:0:0:1",
        "::1"
    ));
    assert!(!record_value_matches(&RecordType::AAAA, "::1", "::2"));
    assert!(record_value_matches(
        &RecordType::NS,
        "ns1.example.com",
        "ns1.example.com."
    ));
}

#[test]
fn rr_to_record_value_splits_srv_priority_into_its_own_column() {
    // priority 10, weight 20, port 5060, target sip.example.com.
    let mut rdata = vec![0, 10, 0, 20, 0x13, 0xC4];
    rdata.extend_from_slice(&[
        3, b's', b'i', b'p', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    let update = update_record(Rtype::SRV, Class::IN, 300, rdata.clone());

    let (record_type, value, priority) = rr_to_record_value(&update, &rdata).unwrap();

    assert_eq!(record_type, RecordType::SRV);
    // The wire encoder reads back this 3-field form with the priority column.
    assert_eq!(value, "20 5060 sip.example.com.");
    assert_eq!(priority, Some(10));
}

fn update_record(rr_type: Rtype, class: Class, ttl: u32, rdata: Vec<u8>) -> UpdateRecord {
    UpdateRecord {
        name: "www.example.com.".to_string(),
        rr_type,
        class,
        ttl,
        rdata,
        rdata_start: 0,
    }
}
