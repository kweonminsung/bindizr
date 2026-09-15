use std::sync::Arc;

use bindizr_core::dns::name::{OwnerName, ZoneName};
use chrono::Utc;

use super::{Caller, RecordWrite, authorize_with_grants};
use crate::{
    error::ErrorCode,
    model::{record::RecordType, token_grant::TokenGrant, zone::Zone},
};

/// Build a zone fixture for the test.
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
        parent_ns_addrs: None,
        enabled: true,
        description: None,
        created_at: Utc::now(),
    }
}

/// Build a grant fixture with the requested name and type filters.
fn grant(pattern: &str, types: &str) -> TokenGrant {
    TokenGrant {
        id: 1,
        zone_id: 1,
        api_token_id: 3,
        record_name_pattern: pattern.to_string(),
        record_types: types.to_string(),
        can_write: true,
        created_at: Utc::now(),
    }
}

/// Check fixture record writes against the supplied token grants.
fn authorize(
    grants: &[TokenGrant],
    writes: &[RecordWrite<'_>],
) -> Result<(), crate::error::ServiceError> {
    authorize_with_grants(grants, &test_zone(), writes)
}

/// Build a record-write authorization target for the test.
fn write<'a>(name: &'a str, record_type: Option<&'a RecordType>) -> RecordWrite<'a> {
    RecordWrite {
        relative_name: OwnerName::from_row(name),
        record_type,
    }
}

/// Verify that `require_global` rejects scoped tokens.
#[test]
fn require_global_rejects_scoped_tokens() {
    assert!(Caller::Global.require_global("create zones").is_ok());

    let scoped = Caller::Token {
        id: 3,
        name: "scoped".into(),
        grants: Arc::from(vec![]),
    };
    let err = scoped.require_global("create zones").unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
    assert!(err.message.contains("create zones"));
}

/// Verify that `authorize` grants writes matching pattern and types.
#[test]
fn authorize_grants_writes_matching_pattern_and_types() {
    let grants = [grant("*", "*")];

    assert!(authorize(&grants, &[write("app", Some(&RecordType::A))]).is_ok());
    assert!(authorize(&grants, &[write("@", None)]).is_ok());
}

/// Verify that `authorize` rejects writes without any grant.
#[test]
fn authorize_rejects_writes_without_any_grant() {
    let err = authorize(&[], &[write("app", Some(&RecordType::A))]).unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
    assert!(err.message.contains("example.com"));
}

/// Verify that `authorize` enforces record name patterns.
#[test]
fn authorize_enforces_record_name_patterns() {
    let grants = [grant("*.dyn", "*")];

    assert!(authorize(&grants, &[write("host.dyn", Some(&RecordType::A))]).is_ok());
    assert!(authorize(&grants, &[write("dyn", Some(&RecordType::A))]).is_ok());

    let err = authorize(&grants, &[write("www", Some(&RecordType::A))]).unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
}

/// Verify that `authorize` enforces record types.
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

/// Verify that `authorize` rejects when any single write is denied.
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

/// Verify that `authorize` rejects a read only grant.
#[test]
fn authorize_rejects_a_read_only_grant() {
    let mut read_only = grant("*", "*");
    read_only.can_write = false;

    let err = authorize(&[read_only], &[write("app", Some(&RecordType::A))]).unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
}

/// Build a scoped caller with the supplied token grants.
fn token(grants: Vec<TokenGrant>) -> Caller {
    Caller::Token {
        id: 3,
        name: "scoped".into(),
        grants: Arc::from(grants),
    }
}

/// Check whether the test caller may read the requested record.
fn visible(caller: &Caller, name: &str, record_type: Option<&RecordType>) -> bool {
    caller.record_visible(1, &OwnerName::from_row(name), record_type)
}

/// Verify that `record_visible` narrows reads the way writes are narrowed.
#[test]
fn record_visible_narrows_reads_the_way_writes_are_narrowed() {
    let caller = token(vec![grant("*.dyn", "A,TXT")]);

    assert!(visible(&caller, "host.dyn", Some(&RecordType::A)));
    assert!(!visible(&caller, "www", Some(&RecordType::A)));
    assert!(!visible(&caller, "host.dyn", Some(&RecordType::CNAME)));

    // The derived DNSSEC plane carries no type of the grant's vocabulary, so
    // it reaches only a grant restricting neither name nor type.
    assert!(!visible(&caller, "host.dyn", None));
    assert!(visible(&token(vec![grant("*", "*")]), "host.dyn", None));
}

/// Verify that `record_visible` survives a read only grant.
#[test]
fn record_visible_survives_a_read_only_grant() {
    let mut read_only = grant("*", "*");
    read_only.can_write = false;

    assert!(visible(
        &token(vec![read_only]),
        "app",
        Some(&RecordType::A)
    ));
}

/// Verify that `ensure_zone_unrestricted` rejects a scoped grant.
#[test]
fn ensure_zone_unrestricted_rejects_a_scoped_grant() {
    assert!(
        Caller::Global
            .ensure_zone_unrestricted(&test_zone())
            .is_ok()
    );
    assert!(
        token(vec![grant("*", "*")])
            .ensure_zone_unrestricted(&test_zone())
            .is_ok()
    );

    let err = token(vec![grant("*.dyn", "*")])
        .ensure_zone_unrestricted(&test_zone())
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);

    // A zone with no grant at all keeps reading as absent.
    let err = token(vec![])
        .ensure_zone_unrestricted(&test_zone())
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ZoneNotFound);
}
