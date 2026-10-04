use bindizr_core::{
    dns::{
        Serial, SoaInterval, Ttl,
        name::{OwnerName, ZoneName},
    },
    model::{
        api_token::{ApiToken, TokenId},
        role::RoleId,
        role_grant::{Action, RoleGrant, RoleGrantId, RoleGrants, RoleZoneScope},
        zone::ZoneId,
    },
};
use chrono::Utc;

use super::*;
use crate::{
    error::ErrorCode,
    model::{record::RecordType, zone::Zone},
};

/// Build a zone fixture for the test.
fn test_zone() -> Zone {
    Zone {
        id: ZoneId::from(1),
        name: ZoneName::from_row("example.com"),
        mname: "ns1.example.com".to_string(),
        rname: "hostmaster@example.com".to_string(),
        default_ttl: Ttl::from_secs(3600),
        serial: Serial::from(1),
        refresh: SoaInterval::from_secs(7200),
        retry: SoaInterval::from_secs(3600),
        expire: SoaInterval::from_secs(604800),
        minimum_ttl: Ttl::from_secs(86400),
        dnssec_policy_id: None,
        parent_ns_addrs: None,
        enabled: true,
        description: None,
        created_at: Utc::now(),
    }
}

/// Build a grant on the fixture zone with the given actions and record constraints.
fn grant(actions: &[Action], pattern: &str, types: &str) -> RoleGrant {
    RoleGrant {
        id: RoleGrantId::from(1),
        role_id: RoleId::from(3),
        zone_scope: RoleZoneScope::Zone(ZoneId::from(1)),
        actions: actions.iter().copied().collect(),
        record_name_pattern: pattern.to_string(),
        record_types: types.to_string(),
        created_at: Utc::now(),
    }
}

/// Build a grant reaching all zones with the given actions.
fn all_zones(actions: &[Action]) -> RoleGrant {
    RoleGrant {
        zone_scope: RoleZoneScope::All,
        ..grant(actions, "*", "*")
    }
}

/// Check fixture record writes against the supplied grants.
fn authorize(grants: &[RoleGrant], writes: &[RecordWrite<'_>]) -> Result<(), ServiceError> {
    authorize_with_grants(&RoleGrants::from(grants.to_vec()), &test_zone(), writes)
}

/// Build a record-create authorization target for the test.
fn create<'a>(name: &'a str, record_type: Option<&'a RecordType>) -> RecordWrite<'a> {
    RecordWrite {
        action: Action::RecordCreate,
        relative_name: OwnerName::from_row(name),
        record_type,
    }
}

/// Build a token row authenticating into role 3.
fn token_record() -> ApiToken {
    ApiToken {
        id: TokenId::from(3),
        name: "deploy".to_string(),
        token: String::new(),
        description: None,
        role_id: RoleId::from(3),
        created_at: Utc::now(),
        expires_at: None,
        last_used_at: None,
    }
}

/// Build a role-scoped caller with the supplied grants.
fn token(grants: Vec<RoleGrant>) -> Caller {
    Caller::from_token(&token_record(), grants)
}

/// Verify that actions on objects no zone owns need a grant covering all zones.
#[test]
fn authorize_action_needs_an_all_zones_grant() {
    assert!(
        Caller::socket()
            .authorize_action(Action::ZoneCreate)
            .is_ok()
    );
    assert!(
        token(vec![all_zones(&[Action::ZoneCreate])])
            .authorize_action(Action::ZoneCreate)
            .is_ok()
    );

    let one_zone = token(vec![grant(&[Action::ZoneCreate], "*", "*")]);
    let err = one_zone.authorize_action(Action::ZoneCreate).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Forbidden);
    assert!(err.to_string().contains("zone:create"));
}

/// Verify that a zone action is 404 without a grant reaching the zone and 403 without the action.
#[test]
fn authorize_zone_action_hides_unreached_zones() {
    let zone = test_zone();

    assert!(
        token(vec![grant(&[Action::ZoneUpdate], "*", "*")])
            .authorize_zone_action(Action::ZoneUpdate, &zone)
            .is_ok()
    );
    assert!(
        token(vec![all_zones(&[Action::ZoneUpdate])])
            .authorize_zone_action(Action::ZoneUpdate, &zone)
            .is_ok()
    );

    let err = token(vec![grant(&[Action::RecordRead], "*", "*")])
        .authorize_zone_action(Action::ZoneUpdate, &zone)
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Forbidden);

    let err = token(vec![])
        .authorize_zone_action(Action::ZoneUpdate, &zone)
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::ZoneNotFound);
}

/// Verify that record writes need the write's action under matching constraints.
#[test]
fn authorize_enforces_action_name_and_type() {
    let grants = [grant(&[Action::RecordCreate], "*.dyn", "A,TXT")];

    assert!(authorize(&grants, &[create("host.dyn", Some(&RecordType::A))]).is_ok());
    assert!(authorize(&grants, &[create("dyn", Some(&RecordType::Txt))]).is_ok());
    assert!(authorize(&grants, &[create("www", Some(&RecordType::A))]).is_err());
    assert!(authorize(&grants, &[create("host.dyn", Some(&RecordType::Cname))]).is_err());
    // A typeless write (whole-name delete) needs a grant constraining no type.
    assert!(authorize(&grants, &[create("host.dyn", None)]).is_err());

    let delete = RecordWrite {
        action: Action::RecordDelete,
        ..create("host.dyn", Some(&RecordType::A))
    };
    let err = authorize(&grants, &[delete]).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Forbidden);
    assert!(err.to_string().contains("record:delete"));
}

/// Verify that `authorize` rejects when any single write is denied.
#[test]
fn authorize_rejects_when_any_single_write_is_denied() {
    let grants = [grant(&[Action::RecordCreate], "app", "*")];

    let err = authorize(
        &grants,
        &[
            create("app", Some(&RecordType::A)),
            create("other", Some(&RecordType::A)),
        ],
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Forbidden);
    assert!(err.to_string().contains("other"));
}

/// Check whether the test caller may read the requested record.
fn visible(caller: &Caller, name: &str, record_type: Option<&RecordType>) -> bool {
    caller.sees_record(ZoneId::from(1), &OwnerName::from_row(name), record_type)
}

/// Verify that `reaches_record` lets a write-only grant find the records it
/// may change, and nothing else.
#[test]
fn reaches_record_admits_the_write_action_under_its_constraints() {
    let caller = token(vec![grant(
        &[Action::RecordDelete],
        "_acme-challenge",
        "TXT",
    )]);
    let reaches = |action, name: &str, record_type: &RecordType| {
        caller.reaches_record(
            action,
            ZoneId::from(1),
            &OwnerName::from_row(name),
            Some(record_type),
        )
    };

    assert!(reaches(
        Action::RecordDelete,
        "_acme-challenge",
        &RecordType::Txt
    ));
    // Nothing beyond the grant's own targets, so ids stay unprobeable.
    assert!(!reaches(
        Action::RecordUpdate,
        "_acme-challenge",
        &RecordType::Txt
    ));
    assert!(!reaches(Action::RecordDelete, "www", &RecordType::Txt));
    assert!(!reaches(
        Action::RecordDelete,
        "_acme-challenge",
        &RecordType::A
    ));
    assert!(!visible(&caller, "_acme-challenge", Some(&RecordType::Txt)));
}

/// Verify that `sees_record` needs `record:read` and narrows like writes.
#[test]
fn sees_record_needs_record_read_under_matching_constraints() {
    let caller = token(vec![grant(&[Action::RecordRead], "*.dyn", "A,TXT")]);

    assert!(visible(&caller, "host.dyn", Some(&RecordType::A)));
    assert!(!visible(&caller, "www", Some(&RecordType::A)));
    assert!(!visible(&caller, "host.dyn", Some(&RecordType::Cname)));

    // The derived DNSSEC plane carries no type of the grant's vocabulary, so
    // it reaches only a grant restricting neither name nor type.
    assert!(!visible(&caller, "host.dyn", None));
    let whole = token(vec![grant(&[Action::RecordRead], "*", "*")]);
    assert!(visible(&whole, "host.dyn", None));

    let write_only = token(vec![grant(&[Action::RecordCreate], "*", "*")]);
    assert!(!visible(&write_only, "app", Some(&RecordType::A)));
}

/// Verify that `authorize_whole_zone` rejects a constrained grant.
#[test]
fn authorize_whole_zone_rejects_a_constrained_grant() {
    let zone = test_zone();
    let read = Action::RecordRead;

    assert!(Caller::socket().authorize_whole_zone(read, &zone).is_ok());
    assert!(
        token(vec![grant(&[read], "*", "*")])
            .authorize_whole_zone(read, &zone)
            .is_ok()
    );

    let err = token(vec![grant(&[read], "*.dyn", "*")])
        .authorize_whole_zone(read, &zone)
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Forbidden);

    // A zone with no grant at all keeps reading as absent.
    let err = token(vec![]).authorize_whole_zone(read, &zone).unwrap_err();
    assert_eq!(err.code(), ErrorCode::ZoneNotFound);
}

/// Equally privileged socket and API callers retain distinct request origins.
#[test]
fn access_scope_does_not_determine_change_attribution() {
    use crate::model::zone_version::{ChangeActor, ChangeSource};

    let socket = Caller::socket();
    let api = Caller::unauthenticated_api();
    for caller in [&socket, &api] {
        assert!(caller.authorize_action(Action::ZoneCreate).is_ok());
        assert_eq!(caller.scope_role_id(), None);
    }
    assert_eq!(socket.change_attribution().source, ChangeSource::Socket);
    assert_eq!(api.change_attribution().source, ChangeSource::Api);
    assert_eq!(socket.change_attribution().actor, None);
    assert_eq!(api.change_attribution().actor, None);

    let admin = token(vec![all_zones(&Action::ALL)]);
    let scoped = token(vec![]);
    assert_eq!(admin.change_attribution(), scoped.change_attribution());
    assert_eq!(
        admin.change_attribution().actor,
        Some(ChangeActor::Token {
            name: "deploy".to_string()
        })
    );
    assert_eq!(scoped.scope_role_id(), Some(RoleId::from(3)));
    assert!(scoped.authorize_action(Action::ZoneCreate).is_err());
}
