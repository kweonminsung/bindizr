//! ANY-class deletions require zero TTL and empty RDATA (RFC 2136, Section 2.5.2).
//! NONE-class deletions require zero TTL and identify a specific record through
//! RDATA (RFC 2136, Section 2.5.4).

use bindizr_core::dns::{
    message::{Class, Rtype},
    nsupdate::parser::UpdateRr,
};

use super::{UpdateError, validate_delete_shape};

/// Verify that an ANY-class deletion accepts zero TTL and empty RDATA.
#[test]
fn validate_delete_shape_accepts_any_class_rrset_delete() {
    let rr = update_rr(Rtype::A, Class::ANY, 0, Vec::new());

    validate_delete_shape(&rr, true).unwrap();
}

/// Verify that a NONE-class deletion accepts a specific record's RDATA.
#[test]
fn validate_delete_shape_accepts_none_class_exact_delete() {
    let rr = update_rr(Rtype::A, Class::NONE, 0, vec![192, 0, 2, 1]);

    validate_delete_shape(&rr, false).unwrap();
}

/// Verify that deletions reject a nonzero TTL.
#[test]
fn validate_delete_shape_rejects_delete_with_nonzero_ttl() {
    let rr = update_rr(Rtype::A, Class::ANY, 60, Vec::new());
    let err = validate_delete_shape(&rr, true).unwrap_err();

    assert!(matches!(err, UpdateError::Refused(_)));
}

/// Verify that an ANY-class deletion rejects RDATA.
#[test]
fn validate_delete_shape_rejects_any_class_delete_with_rdata() {
    let rr = update_rr(Rtype::A, Class::ANY, 0, vec![192, 0, 2, 1]);
    let err = validate_delete_shape(&rr, true).unwrap_err();

    assert!(matches!(err, UpdateError::Refused(_)));
}

/// Verify that a NONE-class deletion requires RDATA.
#[test]
fn validate_delete_shape_rejects_none_class_delete_without_rdata() {
    let rr = update_rr(Rtype::A, Class::NONE, 0, Vec::new());
    let err = validate_delete_shape(&rr, false).unwrap_err();

    assert!(matches!(err, UpdateError::Refused(_)));
}

/// Verify that a NONE-class deletion requires a specific record type.
#[test]
fn validate_delete_shape_rejects_none_class_delete_with_type_any() {
    let rr = update_rr(Rtype::ANY, Class::NONE, 0, vec![192, 0, 2, 1]);
    let err = validate_delete_shape(&rr, false).unwrap_err();

    assert!(matches!(err, UpdateError::Refused(_)));
}

/// Build a dynamic update record with the requested wire fields.
fn update_rr(rr_type: Rtype, class: Class, ttl: u32, rdata: Vec<u8>) -> UpdateRr {
    UpdateRr {
        name: "www.example.com.".to_string(),
        rr_type,
        class,
        ttl,
        rdata,
        rdata_start: 0,
    }
}
