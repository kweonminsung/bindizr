use bindizr_core::dns::{
    message::{Class, Rtype},
    nsupdate::parser::UpdateRecord,
};

use super::{UpdateError, validate_delete_shape};

// Delete-update wire shapes are fixed by RFC 2136: delete-RRset is CLASS ANY +
// TTL 0 + empty RDATA (Section 2.5.2), delete-specific-RR is CLASS NONE + TTL 0 +
// RDATA present (Section 2.5.4); every other combination must be refused.
#[test]
fn validate_delete_shape_accepts_any_class_rrset_delete() {
    let update = update_record(Rtype::A, Class::ANY, 0, Vec::new());

    validate_delete_shape(&update, true).unwrap();
}

#[test]
fn validate_delete_shape_accepts_none_class_exact_delete() {
    let update = update_record(Rtype::A, Class::NONE, 0, vec![192, 0, 2, 1]);

    validate_delete_shape(&update, false).unwrap();
}

#[test]
fn validate_delete_shape_rejects_delete_with_nonzero_ttl() {
    let update = update_record(Rtype::A, Class::ANY, 60, Vec::new());
    let err = validate_delete_shape(&update, true).unwrap_err();

    assert!(matches!(err, UpdateError::Refused(_)));
}

#[test]
fn validate_delete_shape_rejects_any_class_delete_with_rdata() {
    let update = update_record(Rtype::A, Class::ANY, 0, vec![192, 0, 2, 1]);
    let err = validate_delete_shape(&update, true).unwrap_err();

    assert!(matches!(err, UpdateError::Refused(_)));
}

#[test]
fn validate_delete_shape_rejects_none_class_delete_without_rdata() {
    let update = update_record(Rtype::A, Class::NONE, 0, Vec::new());
    let err = validate_delete_shape(&update, false).unwrap_err();

    assert!(matches!(err, UpdateError::Refused(_)));
}

#[test]
fn validate_delete_shape_rejects_none_class_delete_with_type_any() {
    let update = update_record(Rtype::ANY, Class::NONE, 0, vec![192, 0, 2, 1]);
    let err = validate_delete_shape(&update, false).unwrap_err();

    assert!(matches!(err, UpdateError::Refused(_)));
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
