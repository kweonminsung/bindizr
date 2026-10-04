use chrono::Utc;
use serde_json::json;

use super::*;

/// Verify that `Action` has one spelling across `as_str`, serde, and `FromStr`.
#[test]
fn action_spells_itself_once() {
    for action in Action::ALL {
        assert_eq!(
            serde_json::to_value(action).unwrap(),
            json!(action.as_str())
        );
        assert_eq!(
            serde_json::from_value::<Action>(json!(action.as_str())).unwrap(),
            action
        );
        assert_eq!(action.as_str().parse::<Action>().unwrap(), action);
    }
}

/// Verify that an action set keeps one row spelling whatever order it was given in.
#[test]
fn action_set_row_form_is_canonical() {
    let set: ActionSet = [Action::RecordDelete, Action::ZoneRead, Action::RecordDelete]
        .into_iter()
        .collect();

    assert_eq!(set.to_string(), "zone:read,record:delete");
    assert_eq!(ActionSet::try_from(set.to_string()).unwrap(), set);
    assert!(ActionSet::try_from("zone:read,zone:own".to_string()).is_err());
}

/// Verify that an all-zones scope reaches all zones and a zone scope only its own.
#[test]
fn zone_scope_reaches_its_zones() {
    let zone = ZoneId::from(1);

    assert!(RoleZoneScope::from(None).covers(zone));
    assert!(RoleZoneScope::from(Some(zone)).covers(zone));
    assert!(!RoleZoneScope::Zone(ZoneId::from(2)).covers(zone));
}

/// Build a grant of `actions` in `scope`, narrowed by `pattern` and `types`.
fn grant(scope: RoleZoneScope, actions: &[Action], pattern: &str, types: &str) -> RoleGrant {
    RoleGrant {
        id: RoleGrantId::from(1),
        role_id: RoleId::from(1),
        zone_scope: scope,
        actions: actions.iter().copied().collect(),
        record_name_pattern: pattern.to_string(),
        record_types: types.to_string(),
        created_at: Utc::now(),
    }
}

/// Verify that a role's rights are the union of its grants, each kept to its
/// own zone, name, and type.
#[test]
fn role_grants_answer_over_their_union() {
    let zone = ZoneId::from(1);
    let other = ZoneId::from(2);
    let grants = RoleGrants::from(vec![
        grant(RoleZoneScope::All, &[Action::RecordRead], "*", "*"),
        grant(
            RoleZoneScope::Zone(zone),
            &[Action::RecordCreate],
            "*.dyn",
            "A",
        ),
    ]);
    let host = OwnerName::from_row("host.dyn");

    assert!(grants.permits(Action::RecordRead, other));
    assert!(grants.permits(Action::RecordCreate, zone));
    assert!(!grants.permits(Action::RecordCreate, other));
    assert!(grants.covers_record(Action::RecordCreate, zone, &host, Some(&RecordType::A)));
    assert!(!grants.covers_record(Action::RecordCreate, zone, &host, Some(&RecordType::Txt)));
    assert!(grants.covers_whole_zone(Action::RecordRead, zone));
    assert!(!grants.covers_whole_zone(Action::RecordCreate, zone));
    assert!(grants.reaches_zone(other));
    // Only an all-zones grant carries an action in all zones.
    assert!(grants.permits_all_zones(Action::RecordRead));
    assert!(!grants.permits_all_zones(Action::RecordCreate));
}

/// Verify that a pattern holds actions split across its own grants and those
/// naming any name, and not ones only another pattern holds.
#[test]
fn patterns_holding_unions_grants_per_pattern() {
    let zone = ZoneId::from(1);
    let sync = [
        Action::RecordRead,
        Action::RecordCreate,
        Action::RecordDelete,
    ];
    let grants = RoleGrants::from(vec![
        grant(RoleZoneScope::All, &[Action::RecordRead], "*", "*"),
        grant(
            RoleZoneScope::Zone(zone),
            &[Action::RecordCreate, Action::RecordDelete],
            "*.k8s",
            "*",
        ),
        grant(
            RoleZoneScope::Zone(zone),
            &[Action::RecordCreate],
            "*.web",
            "*",
        ),
    ]);

    assert_eq!(
        grants
            .patterns_holding(zone, &sync)
            .into_iter()
            .collect::<Vec<_>>(),
        vec!["*.k8s"]
    );
    assert!(grants.patterns_holding(ZoneId::from(2), &sync).is_empty());

    // Split across grants, the actions must still share a record type.
    let disjoint = RoleGrants::from(vec![
        grant(
            RoleZoneScope::Zone(zone),
            &[Action::RecordRead, Action::RecordCreate],
            "*.a",
            "A",
        ),
        grant(
            RoleZoneScope::Zone(zone),
            &[Action::RecordDelete],
            "*.a",
            "TXT",
        ),
        grant(
            RoleZoneScope::Zone(zone),
            &[Action::RecordRead],
            "*.b",
            "A,TXT",
        ),
        grant(
            RoleZoneScope::Zone(zone),
            &[Action::RecordCreate, Action::RecordDelete],
            "*.b",
            "TXT",
        ),
    ]);
    assert_eq!(
        disjoint
            .patterns_holding(zone, &sync)
            .into_iter()
            .collect::<Vec<_>>(),
        vec!["*.b"]
    );

    // An enclosing subtree lends its actions to the narrower pattern inside it.
    let nested = RoleGrants::from(vec![
        grant(
            RoleZoneScope::Zone(zone),
            &[Action::RecordRead],
            "*.apps",
            "*",
        ),
        grant(
            RoleZoneScope::Zone(zone),
            &[Action::RecordCreate, Action::RecordDelete],
            "api.apps",
            "*",
        ),
    ]);
    assert_eq!(
        nested
            .patterns_holding(zone, &sync)
            .into_iter()
            .collect::<Vec<_>>(),
        vec!["api.apps"]
    );
}
