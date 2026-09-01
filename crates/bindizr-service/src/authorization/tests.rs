use std::sync::Arc;

use bindizr_core::dns::name::{OwnerName, ZoneName};
use chrono::Utc;

use super::{Caller, RecordWrite, authorize_with_policies};
use crate::{
    error::ErrorCode,
    model::{
        record::RecordType,
        zone::{DnssecDenial, Zone},
        zone_token_policy::ZoneTokenPolicy,
    },
};

fn test_zone() -> Zone {
    Zone {
        id: 1,
        name: ZoneName::from_row("example.com"),
        mname: "ns1.example.com".to_string(),
        rname: "hostmaster@example.com".to_string(),
        default_ttl: 3600,
        serial: 1,
        refresh: 7200,
        retry: 3600,
        expire: 604800,
        minimum_ttl: 86400,
        dnssec_denial: DnssecDenial::Nsec,
        dnssec_signature_validity_days: None,
        dnssec_signature_refresh_days: None,
        dnssec_zsk_lifetime_days: None,
        created_at: Utc::now(),
    }
}

fn policy(pattern: &str, types: &str) -> ZoneTokenPolicy {
    ZoneTokenPolicy {
        id: 1,
        zone_id: 1,
        api_token_id: 3,
        record_name_pattern: pattern.to_string(),
        record_types: types.to_string(),
        created_at: Utc::now(),
    }
}

fn authorize(
    policies: &[ZoneTokenPolicy],
    writes: &[RecordWrite<'_>],
) -> Result<(), crate::error::ServiceError> {
    authorize_with_policies(policies, &test_zone(), writes)
}

fn write<'a>(name: &'a str, record_type: Option<&'a RecordType>) -> RecordWrite<'a> {
    RecordWrite {
        relative_name: OwnerName::from_row(name),
        record_type,
    }
}

#[test]
fn require_global_rejects_scoped_tokens() {
    assert!(Caller::Global.require_global("create zones").is_ok());

    let scoped = Caller::Token {
        id: 3,
        grants: Arc::from(vec![]),
    };
    let err = scoped.require_global("create zones").unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
    assert!(err.message.contains("create zones"));
}

#[test]
fn authorize_grants_writes_matching_pattern_and_types() {
    let policies = [policy("*", "*")];

    assert!(authorize(&policies, &[write("app", Some(&RecordType::A))]).is_ok());
    assert!(authorize(&policies, &[write("@", None)]).is_ok());
}

#[test]
fn authorize_rejects_writes_without_any_policy() {
    let err = authorize(&[], &[write("app", Some(&RecordType::A))]).unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
    assert!(err.message.contains("example.com"));
}

#[test]
fn authorize_enforces_record_name_patterns() {
    let policies = [policy("*.dyn", "*")];

    assert!(authorize(&policies, &[write("host.dyn", Some(&RecordType::A))]).is_ok());
    assert!(authorize(&policies, &[write("dyn", Some(&RecordType::A))]).is_ok());

    let err = authorize(&policies, &[write("www", Some(&RecordType::A))]).unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
}

#[test]
fn authorize_enforces_record_types() {
    let policies = [policy("*", "A,TXT")];

    assert!(authorize(&policies, &[write("app", Some(&RecordType::A))]).is_ok());
    assert!(authorize(&policies, &[write("app", Some(&RecordType::TXT))]).is_ok());

    let err = authorize(&policies, &[write("app", Some(&RecordType::CNAME))]).unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);

    // A typeless write (whole-name delete) needs an unrestricted-type policy.
    let err = authorize(&policies, &[write("app", None)]).unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
}

#[test]
fn authorize_rejects_when_any_single_write_is_denied() {
    let policies = [policy("app", "*")];

    let err = authorize(
        &policies,
        &[
            write("app", Some(&RecordType::A)),
            write("other", Some(&RecordType::A)),
        ],
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
    assert!(err.message.contains("other"));
}
