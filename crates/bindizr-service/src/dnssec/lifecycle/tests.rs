use bindizr_core::{
    dns::name::ZoneName,
    model::{dnssec_key::DnssecAlgorithm, dnssec_policy::DnssecDenial},
};

use super::*;

/// Build the test zone or its DNS name.
fn zone() -> Zone {
    Zone {
        id: 1,
        name: ZoneName::parse("example.com").unwrap(),
        mname: "ns1.example.com".to_string(),
        rname: "admin@example.com".to_string(),
        default_ttl: 300,
        serial: 5,
        refresh: 300,
        retry: 60,
        expire: 3600000,
        minimum_ttl: 900,
        dnssec_policy_id: Some(1),
        parent_ns_addrs: None,
        enabled: true,
        description: None,
        created_at: Utc::now(),
    }
}

/// Build a DNSSEC policy fixture with the requested identity.
fn policy(id: i32, name: &str) -> DnssecPolicy {
    DnssecPolicy {
        id,
        name: name.to_string(),
        algorithm: DnssecAlgorithm::EcdsaP256Sha256,
        denial: DnssecDenial::Nsec,
        split_keys: false,
        signature_validity_days: 14,
        signature_refresh_days: 5,
        zsk_lifetime_days: 0,
        created_at: Utc::now(),
    }
}

/// Verify that a move that only changes timings is allowed.
#[test]
fn a_move_that_only_changes_timings_is_allowed() {
    let current = policy(1, "default");
    let mut target = policy(2, "long-lived");
    target.signature_validity_days = 30;
    target.zsk_lifetime_days = 90;

    validate_policy_move(&zone(), &current, &target).unwrap();
}

/// Verify that a move that only changes the algorithm is left to the rollover.
#[test]
fn a_move_that_only_changes_the_algorithm_is_left_to_the_rollover() {
    let current = policy(1, "default");
    let mut target = policy(2, "ed25519");
    target.algorithm = DnssecAlgorithm::Ed25519;

    validate_policy_move(&zone(), &current, &target).unwrap();
}

/// Verify that a move that changes the denial chain is allowed in place.
#[test]
fn a_move_that_changes_the_denial_chain_is_allowed_in_place() {
    // No key roll stands between the two chains: every algorithm bindizr
    // signs with is NSEC3-capable (RFC 5155, Section 2).
    let current = policy(1, "default");
    let mut target = policy(2, "nsec3");
    target.denial = DnssecDenial::Nsec3;

    validate_policy_move(&zone(), &current, &target).unwrap();

    validate_policy_move(&zone(), &target, &current).unwrap();
}

/// Verify that the key layout cannot change under a signed zone.
#[test]
fn the_key_layout_cannot_change_under_a_signed_zone() {
    let current = policy(1, "default");
    let mut target = policy(2, "split");
    target.split_keys = true;

    let error = validate_policy_move(&zone(), &current, &target).unwrap_err();

    assert!(error.message.contains("key layout"), "{}", error.message);
    assert!(
        error.message.contains("split KSK/ZSK keys"),
        "{}",
        error.message
    );
}

/// Verify that the key layout is still refused when the denial chain moves with it.
#[test]
fn the_key_layout_is_still_refused_when_the_denial_chain_moves_with_it() {
    let current = policy(1, "default");
    let mut target = policy(2, "other");
    target.denial = DnssecDenial::Nsec3;
    target.split_keys = true;

    let error = validate_policy_move(&zone(), &current, &target).unwrap_err();

    assert!(error.message.contains("key layout"), "{}", error.message);
}
