use std::error::Error as _;
use std::io;

use serde_json::json;

use super::*;
use crate::dns_client::ResolveAddressError;
use crate::dns_client::ds::ProbeParentDsError;

/// Verify that input policy errors have no underlying operation failure to retain.
#[test]
fn invalid_input_keeps_its_code_and_message_without_an_artificial_source() {
    for error in [
        ServiceError::invalid_input("invalid input"),
        ServiceError::record_name_ambiguous("example.com", "www", 2),
    ] {
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.source().is_none());
    }

    assert_eq!(
        ServiceError::invalid_input("invalid input").to_string(),
        "invalid input"
    );
    assert_eq!(
        ServiceError::record_name_ambiguous("example.com", "www", 2).to_string(),
        "2 records are named 'www' in zone 'example.com'; address one by its id"
    );
}

/// Verify that the cause stays available after assigning the public DS-check classification.
#[test]
fn ds_check_failure_preserves_source_and_wire_message() {
    let error = ServiceError::dnssec_ds_unverified(
        "example.com",
        ProbeParentDsError::Unresolved {
            entry: "ns.parent.example".to_string(),
            source: ResolveAddressError::Lookup(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "resolver disconnected",
            )),
        },
    );

    assert_eq!(error.code(), ErrorCode::DnssecDsUnverified);
    assert_eq!(
        error.to_string(),
        "could not ask the parent zone for the DS of zone 'example.com': \
         parent server 'ns.parent.example' did not resolve: resolver disconnected"
    );
    let source = error.source().unwrap();

    assert!(matches!(
        source.downcast_ref::<ProbeParentDsError>(),
        Some(ProbeParentDsError::Unresolved { entry, .. }) if entry == "ns.parent.example"
    ));
    assert!(matches!(
        source.source().unwrap().downcast_ref::<ResolveAddressError>(),
        Some(ResolveAddressError::Lookup(error))
            if error.kind() == io::ErrorKind::ConnectionReset
    ));
}

/// Verify that an unsupported digest is the observed policy outcome, without an underlying failure.
#[test]
fn unsupported_ds_digest_preserves_policy_message_without_source() {
    let error = ServiceError::dnssec_ds_digest_unsupported("example.com", &[KeyTag::from(7)]);

    assert_eq!(error.code(), ErrorCode::DnssecDsUnverified);
    assert_eq!(
        error.to_string(),
        "the parent zone serves a DS for key tag 7 of zone 'example.com', but only in digest \
         types bindizr cannot compute, so the match cannot be confirmed; ask the parent \
         to publish SHA-256, or skip the DS check"
    );
    assert!(error.source().is_none());
}

/// Verify that a signing failure is not an internal error.
#[test]
fn signing_failure_preserves_dnssec_error_class() {
    let error = ServiceError::dnssec_signing_failed(io::Error::other("boom"));
    assert_eq!(error.code(), ErrorCode::DnssecSigningFailed);
    assert!(error.code().is_internal());
}

/// Verify that the concrete source is preserved when an internal failure gains context.
#[test]
fn internal_context_preserves_the_source() {
    let error = ServiceError::internal_with_source(
        "failed to load records",
        io::Error::new(io::ErrorKind::ConnectionReset, "database disconnected"),
    );

    assert_eq!(error.code(), ErrorCode::Internal);
    assert_eq!(error.to_string(), "failed to load records");
    let source = error.source().unwrap().downcast_ref::<io::Error>().unwrap();

    assert_eq!(source.kind(), io::ErrorKind::ConnectionReset);
}

/// Verify that `ErrorCode` has one spelling across `as_str` and serde.
#[test]
fn error_code_spells_itself_once() {
    for (value, expected) in [
        (ErrorCode::InvalidInput, "INVALID_INPUT"),
        (ErrorCode::InvalidZoneField, "INVALID_ZONE_FIELD"),
        (ErrorCode::InvalidRecordName, "INVALID_RECORD_NAME"),
        (ErrorCode::InvalidRecordValue, "INVALID_RECORD_VALUE"),
        (ErrorCode::InvalidJsonBody, "INVALID_JSON_BODY"),
        (ErrorCode::ZoneConflict, "ZONE_CONFLICT"),
        (ErrorCode::RecordConflict, "RECORD_CONFLICT"),
        (ErrorCode::TokenConflict, "TOKEN_CONFLICT"),
        (ErrorCode::EndpointNotFound, "ENDPOINT_NOT_FOUND"),
        (ErrorCode::MethodNotAllowed, "METHOD_NOT_ALLOWED"),
        (ErrorCode::ZoneNotFound, "ZONE_NOT_FOUND"),
        (ErrorCode::RecordNotFound, "RECORD_NOT_FOUND"),
        (ErrorCode::TokenNotFound, "TOKEN_NOT_FOUND"),
        (ErrorCode::VersionNotFound, "VERSION_NOT_FOUND"),
        (ErrorCode::SecondaryNotFound, "SECONDARY_NOT_FOUND"),
        (ErrorCode::SecondaryConflict, "SECONDARY_CONFLICT"),
        (ErrorCode::TsigKeyNotFound, "TSIG_KEY_NOT_FOUND"),
        (ErrorCode::TsigKeyConflict, "TSIG_KEY_CONFLICT"),
        (ErrorCode::TsigKeyInUse, "TSIG_KEY_IN_USE"),
        (ErrorCode::RoleNotFound, "ROLE_NOT_FOUND"),
        (ErrorCode::RoleConflict, "ROLE_CONFLICT"),
        (ErrorCode::RoleInUse, "ROLE_IN_USE"),
        (ErrorCode::RoleGrantNotFound, "ROLE_GRANT_NOT_FOUND"),
        (ErrorCode::DnssecAlreadyEnabled, "DNSSEC_ALREADY_ENABLED"),
        (ErrorCode::DnssecNotEnabled, "DNSSEC_NOT_ENABLED"),
        (
            ErrorCode::DnssecRolloverInProgress,
            "DNSSEC_ROLLOVER_IN_PROGRESS",
        ),
        (
            ErrorCode::DnssecNoRolloverInProgress,
            "DNSSEC_NO_ROLLOVER_IN_PROGRESS",
        ),
        (ErrorCode::DnssecDsPublished, "DNSSEC_DS_PUBLISHED"),
        (ErrorCode::DnssecDsNotPublished, "DNSSEC_DS_NOT_PUBLISHED"),
        (ErrorCode::DnssecDsUnverified, "DNSSEC_DS_UNVERIFIED"),
        (ErrorCode::DnssecPolicyNotFound, "DNSSEC_POLICY_NOT_FOUND"),
        (ErrorCode::DnssecPolicyConflict, "DNSSEC_POLICY_CONFLICT"),
        (ErrorCode::DnssecPolicyInUse, "DNSSEC_POLICY_IN_USE"),
        (ErrorCode::DnssecSigningFailed, "DNSSEC_SIGNING_FAILED"),
        (ErrorCode::Unauthorized, "UNAUTHORIZED"),
        (ErrorCode::InvalidToken, "INVALID_TOKEN"),
        (ErrorCode::Forbidden, "FORBIDDEN"),
        (ErrorCode::PayloadTooLarge, "PAYLOAD_TOO_LARGE"),
        (ErrorCode::UnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE"),
        (ErrorCode::Internal, "INTERNAL"),
    ] {
        assert_eq!(value.as_str(), expected);
        assert_eq!(serde_json::to_value(value).unwrap(), json!(expected));
        assert_eq!(
            serde_json::from_value::<ErrorCode>(json!(expected)).unwrap(),
            value
        );
    }
}
