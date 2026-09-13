use chrono::{DateTime, Duration, Utc};

use super::*;
use crate::{dns::name::ZoneName, model::zone::Zone};

/// A real `dnssec-keygen -a ECDSAP256SHA256` pair (BIND 9.20), so the tests
/// hold the field spelling and order bindizr must read, not a guess at it.
const BIND_DNSKEY: &str = "example.com. IN DNSKEY 256 3 13 \
     gSg3RvmCGcoikc9xcWW1fwZYE2m4CRWoel9whdwfdsmTAjArfnuNwMo0 c5232xw2CP2rP9GN5tKllyM4H13eoA==";
const BIND_PRIVATE: &str = "\
Private-key-format: v1.3
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: azlfCEpPN7tJGVHRmdBQRYrBYVkKkpySkoYi7QTO+Yg=
Created: 20260913195832
";

fn test_zone() -> Zone {
    Zone {
        id: 1,
        name: ZoneName::parse("example.com").unwrap(),
        mname: "ns1.example.com".to_string(),
        rname: "admin@example.com".to_string(),
        default_ttl: 3600,
        serial: 5,
        refresh: 300,
        retry: 60,
        expire: 3600000,
        minimum_ttl: 900,
        dnssec_policy_id: None,
        parent_ns_addrs: None,
        enabled: true,
        description: None,
        created_at: Utc::now(),
    }
}

fn now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-09-14T00:00:00Z")
        .unwrap()
        .to_utc()
}

fn stamp(offset_hours: i64) -> String {
    (now() + Duration::hours(offset_hours))
        .format("%Y%m%d%H%M%S")
        .to_string()
}

fn import(timing: &[(&str, String)]) -> Result<DnssecKey, String> {
    let mut private = BIND_PRIVATE.to_string();
    for (field, at) in timing {
        private.push_str(&format!("{}: {}\n", field, at));
    }
    import_key(&test_zone(), true, BIND_DNSKEY, &private, now())
}

#[test]
fn a_key_file_without_timing_imports_as_a_settled_active_key() {
    let key = import(&[]).unwrap();

    assert_eq!(key.state, DnssecKeyState::Active);
    assert_eq!(key.state_changed_at, now());
    assert_eq!(key.eligible_at, now());
}

#[test]
fn bind_timing_places_an_imported_key_in_its_rollover() {
    // Pre-published: signs nothing until its own Activate.
    let key = import(&[("Publish", stamp(-1)), ("Activate", stamp(2))]).unwrap();
    assert_eq!(key.state, DnssecKeyState::Published);
    assert_eq!(key.state_changed_at, now() - Duration::hours(1));
    assert_eq!(key.eligible_at, now() + Duration::hours(2));

    // Active since Activate, which is what the ZSK lifetime counts from.
    let key = import(&[("Publish", stamp(-48)), ("Activate", stamp(-24))]).unwrap();
    assert_eq!(key.state, DnssecKeyState::Active);
    assert_eq!(key.state_changed_at, now() - Duration::hours(24));

    // Retired: still in the DNSKEY RRset until BIND's own Delete.
    let key = import(&[
        ("Publish", stamp(-48)),
        ("Activate", stamp(-24)),
        ("Inactive", stamp(-2)),
        ("Delete", stamp(6)),
    ])
    .unwrap();
    assert_eq!(key.state, DnssecKeyState::Retired);
    assert_eq!(key.state_changed_at, now() - Duration::hours(2));
    assert_eq!(key.eligible_at, now() + Duration::hours(6));
}

#[test]
fn a_schedule_bind_left_open_falls_back_to_the_dnskey_ttl() {
    let ttl = Duration::seconds(i64::from(test_zone().default_ttl));

    let key = import(&[("Publish", stamp(-1))]).unwrap();
    assert_eq!(key.state, DnssecKeyState::Published);
    assert_eq!(key.eligible_at, now() + ttl);

    let key = import(&[("Activate", stamp(-24)), ("Inactive", stamp(-2))]).unwrap();
    assert_eq!(key.state, DnssecKeyState::Retired);
    assert_eq!(key.eligible_at, now() + ttl);
}

#[test]
fn a_key_outside_the_window_bind_serves_it_in_is_refused() {
    let not_yet = import(&[("Publish", stamp(1)), ("Activate", stamp(2))]).unwrap_err();
    assert!(not_yet.contains("not published until"), "{not_yet}");

    let gone = import(&[
        ("Publish", stamp(-48)),
        ("Inactive", stamp(-24)),
        ("Delete", stamp(-1)),
    ])
    .unwrap_err();
    assert!(gone.contains("no longer serves it"), "{gone}");

    let malformed = import(&[("Publish", "not-a-time".to_string())]).unwrap_err();
    assert!(malformed.contains("invalid Publish time"), "{malformed}");
}

#[test]
fn an_exported_key_file_re_imports_in_the_state_it_left() {
    for timing in [
        vec![("Publish", stamp(-1)), ("Activate", stamp(2))],
        vec![("Publish", stamp(-48)), ("Activate", stamp(-24))],
        vec![
            ("Publish", stamp(-48)),
            ("Activate", stamp(-24)),
            ("Inactive", stamp(-2)),
            ("Delete", stamp(6)),
        ],
    ] {
        let key = import(&timing).unwrap();
        let reimported = import_key(
            &test_zone(),
            true,
            BIND_DNSKEY,
            &to_bind_private_file(&key),
            now(),
        )
        .unwrap();

        assert_eq!(reimported.state, key.state);
        assert_eq!(reimported.state_changed_at, key.state_changed_at);
        assert_eq!(reimported.eligible_at, key.eligible_at);
    }
}
