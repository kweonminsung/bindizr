use std::sync::Arc;

use bindizr_core::dns::name::{OwnerName, ZoneName};
use chrono::Utc;

use super::{Caller, RecordWrite, authorize_with_grants};
use crate::{
    error::ErrorCode,
    model::{record::RecordType, token_grant::TokenGrant, zone::Zone},
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
        dnssec_policy_id: None,
        created_at: Utc::now(),
    }
}

fn grant(pattern: &str, types: &str) -> TokenGrant {
    TokenGrant {
        id: 1,
        zone_id: 1,
        api_token_id: 3,
        record_name_pattern: pattern.to_string(),
        record_types: types.to_string(),
        created_at: Utc::now(),
    }
}

fn authorize(
    grants: &[TokenGrant],
    writes: &[RecordWrite<'_>],
) -> Result<(), crate::error::ServiceError> {
    authorize_with_grants(grants, &test_zone(), writes)
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
    let grants = [grant("*", "*")];

    assert!(authorize(&grants, &[write("app", Some(&RecordType::A))]).is_ok());
    assert!(authorize(&grants, &[write("@", None)]).is_ok());
}

#[test]
fn authorize_rejects_writes_without_any_grant() {
    let err = authorize(&[], &[write("app", Some(&RecordType::A))]).unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
    assert!(err.message.contains("example.com"));
}

#[test]
fn authorize_enforces_record_name_patterns() {
    let grants = [grant("*.dyn", "*")];

    assert!(authorize(&grants, &[write("host.dyn", Some(&RecordType::A))]).is_ok());
    assert!(authorize(&grants, &[write("dyn", Some(&RecordType::A))]).is_ok());

    let err = authorize(&grants, &[write("www", Some(&RecordType::A))]).unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
}

#[test]
fn authorize_enforces_record_types() {
    let grants = [grant("*", "A,TXT")];

    assert!(authorize(&grants, &[write("app", Some(&RecordType::A))]).is_ok());
    assert!(authorize(&grants, &[write("app", Some(&RecordType::TXT))]).is_ok());

    let err = authorize(&grants, &[write("app", Some(&RecordType::CNAME))]).unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);

    // A typeless write (whole-name delete) needs an unrestricted-type grant.
    let err = authorize(&grants, &[write("app", None)]).unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
}

#[test]
fn authorize_rejects_when_any_single_write_is_denied() {
    let grants = [grant("app", "*")];

    let err = authorize(
        &grants,
        &[
            write("app", Some(&RecordType::A)),
            write("other", Some(&RecordType::A)),
        ],
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
    assert!(err.message.contains("other"));
}
