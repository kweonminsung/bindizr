use std::sync::Arc;

use chrono::Utc;

use super::{Caller, RecordWrite, authorize_record_writes, require_global};
use crate::{
    error::ErrorCode,
    model::{record::RecordType, zone::Zone, zone_token_policy::ZoneTokenPolicy},
};

fn test_zone() -> Zone {
    Zone {
        id: 1,
        name: "example.com".to_string(),
        primary_ns: "ns1.example.com".to_string(),
        admin_email: "hostmaster@example.com".to_string(),
        ttl: 3600,
        serial: 1,
        refresh: 7200,
        retry: 3600,
        expire: 604800,
        minimum_ttl: 86400,
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

fn scoped(grants: Vec<ZoneTokenPolicy>) -> Caller {
    Caller::Token {
        id: 3,
        grants: Arc::from(grants),
    }
}

fn write<'a>(name: &'a str, record_type: Option<&'a RecordType>) -> RecordWrite<'a> {
    RecordWrite {
        relative_name: name,
        record_type,
    }
}

#[test]
fn require_global_rejects_scoped_tokens() {
    assert!(require_global(&Caller::Global, "create zones").is_ok());

    let err = require_global(&scoped(vec![]), "create zones").unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
    assert!(err.message.contains("create zones"));
}

#[test]
fn authorize_grants_writes_matching_pattern_and_types() {
    let zone = test_zone();
    let caller = scoped(vec![policy("*", "*")]);

    assert!(authorize_record_writes(&caller, &zone, &[write("app", Some(&RecordType::A))]).is_ok());
    assert!(authorize_record_writes(&caller, &zone, &[write("@", None)]).is_ok());
    assert!(
        authorize_record_writes(
            &Caller::Global,
            &zone,
            &[write("app", Some(&RecordType::A))]
        )
        .is_ok()
    );
}

#[test]
fn authorize_rejects_writes_without_any_grant() {
    let zone = test_zone();

    let err = authorize_record_writes(
        &scoped(vec![]),
        &zone,
        &[write("app", Some(&RecordType::A))],
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
    assert!(err.message.contains("example.com"));
}

#[test]
fn authorize_ignores_grants_of_other_zones() {
    let zone = test_zone();
    let mut other_zone_policy = policy("*", "*");
    other_zone_policy.zone_id = 2;
    let caller = scoped(vec![other_zone_policy]);

    let err =
        authorize_record_writes(&caller, &zone, &[write("app", Some(&RecordType::A))]).unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
}

#[test]
fn authorize_enforces_record_name_patterns() {
    let zone = test_zone();
    let caller = scoped(vec![policy("*.dyn", "*")]);

    assert!(
        authorize_record_writes(&caller, &zone, &[write("host.dyn", Some(&RecordType::A))]).is_ok()
    );
    assert!(authorize_record_writes(&caller, &zone, &[write("dyn", Some(&RecordType::A))]).is_ok());

    let err =
        authorize_record_writes(&caller, &zone, &[write("www", Some(&RecordType::A))]).unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
}

#[test]
fn authorize_enforces_record_types() {
    let zone = test_zone();
    let caller = scoped(vec![policy("*", "A,TXT")]);

    assert!(authorize_record_writes(&caller, &zone, &[write("app", Some(&RecordType::A))]).is_ok());
    assert!(
        authorize_record_writes(&caller, &zone, &[write("app", Some(&RecordType::TXT))]).is_ok()
    );

    let err = authorize_record_writes(&caller, &zone, &[write("app", Some(&RecordType::CNAME))])
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);

    // A typeless write (whole-name delete) needs an unrestricted-type policy.
    let err = authorize_record_writes(&caller, &zone, &[write("app", None)]).unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
}

#[test]
fn authorize_rejects_when_any_single_write_is_denied() {
    let zone = test_zone();
    let caller = scoped(vec![policy("app", "*")]);

    let err = authorize_record_writes(
        &caller,
        &zone,
        &[
            write("app", Some(&RecordType::A)),
            write("other", Some(&RecordType::A)),
        ],
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
    assert!(err.message.contains("other"));
}
