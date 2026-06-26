use super::{
    CLASS_ANY, CLASS_IN, CLASS_NONE, TYPE_A, TYPE_ANY, TYPE_TXT, UpdateError, absolute_to_relative,
    normalize_owner_name, record_value_matches, rr_to_record_value, validate_delete_update_shape,
};
use crate::{model::record::RecordType, nsupdate::parser::UpdateRecord};

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

#[test]
fn validate_delete_update_shape_accepts_any_class_rrset_delete() {
    let update = update_record(TYPE_A, CLASS_ANY, 0, Vec::new());

    validate_delete_update_shape(&update, true).unwrap();
}

#[test]
fn validate_delete_update_shape_accepts_none_class_exact_delete() {
    let update = update_record(TYPE_A, CLASS_NONE, 0, vec![192, 0, 2, 1]);

    validate_delete_update_shape(&update, false).unwrap();
}

#[test]
fn validate_delete_update_shape_rejects_delete_with_nonzero_ttl() {
    let update = update_record(TYPE_A, CLASS_ANY, 60, Vec::new());
    let err = validate_delete_update_shape(&update, true).unwrap_err();

    assert!(matches!(err, UpdateError::Refused(_)));
}

#[test]
fn validate_delete_update_shape_rejects_any_class_delete_with_rdata() {
    let update = update_record(TYPE_A, CLASS_ANY, 0, vec![192, 0, 2, 1]);
    let err = validate_delete_update_shape(&update, true).unwrap_err();

    assert!(matches!(err, UpdateError::Refused(_)));
}

#[test]
fn validate_delete_update_shape_rejects_none_class_delete_without_rdata() {
    let update = update_record(TYPE_A, CLASS_NONE, 0, Vec::new());
    let err = validate_delete_update_shape(&update, false).unwrap_err();

    assert!(matches!(err, UpdateError::Refused(_)));
}

#[test]
fn validate_delete_update_shape_rejects_none_class_delete_with_type_any() {
    let update = update_record(TYPE_ANY, CLASS_NONE, 0, vec![192, 0, 2, 1]);
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
        rr_type: TYPE_TXT,
        class: CLASS_IN,
        ttl: 300,
        rdata: vec![2, b'a', b'b', 1, b'c'],
        rdata_start: 0,
    };
    let second = UpdateRecord {
        name: "txt.example.com.".to_string(),
        rr_type: TYPE_TXT,
        class: CLASS_IN,
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

fn update_record(rr_type: u16, class: u16, ttl: u32, rdata: Vec<u8>) -> UpdateRecord {
    UpdateRecord {
        name: "www.example.com.".to_string(),
        rr_type,
        class,
        ttl,
        rdata,
        rdata_start: 0,
    }
}
