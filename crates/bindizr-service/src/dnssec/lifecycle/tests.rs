use bindizr_core::dns::name::ZoneName;
use bindizr_core::dns::{Serial, SoaInterval, Ttl};
use bindizr_core::model::dnssec_key::DnssecAlgorithm;
use bindizr_core::model::dnssec_policy::{Days, DnssecDenial, PolicyId};
use bindizr_core::model::zone::ZoneId;

use super::*;

/// Build the test zone or its DNS name.
fn zone() -> Zone {
    Zone {
        id: ZoneId::from(1),
        name: ZoneName::parse("example.com").unwrap(),
        mname: "ns1.example.com".to_string(),
        rname: "admin@example.com".to_string(),
        default_ttl: Ttl::from_secs(300),
        serial: Serial::from(5),
        refresh: SoaInterval::from_secs(300),
        retry: SoaInterval::from_secs(60),
        expire: SoaInterval::from_secs(3600000),
        minimum_ttl: Ttl::from_secs(900),
        dnssec_policy_id: Some(PolicyId::from(1)),
        parent_ns_addrs: None,
        enabled: true,
        description: None,
        created_at: Utc::now(),
    }
}

/// Build a DNSSEC policy fixture with the requested identity.
fn policy(id: i32, name: &str) -> DnssecPolicy {
    DnssecPolicy {
        id: PolicyId::from(id),
        name: name.to_string(),
        algorithm: DnssecAlgorithm::EcdsaP256Sha256,
        denial: DnssecDenial::Nsec,
        split_keys: false,
        signature_validity_days: Days::try_from(14).unwrap(),
        signature_refresh_days: Days::try_from(5).unwrap(),
        zsk_lifetime_days: Days::try_from(0).unwrap(),
        created_at: Utc::now(),
    }
}

/// Verify that a move that only changes timings is allowed.
#[test]
fn policy_move_accepts_timing_changes() {
    let current = policy(1, "default");
    let mut target = policy(2, "long-lived");
    target.signature_validity_days = Days::try_from(30).unwrap();
    target.zsk_lifetime_days = Days::try_from(90).unwrap();

    validate_policy_move(&zone(), &current, &target).unwrap();
}

/// Verify that a move that only changes the algorithm is left to the rollover.
#[test]
fn policy_move_accepts_algorithm_change() {
    let current = policy(1, "default");
    let mut target = policy(2, "ed25519");
    target.algorithm = DnssecAlgorithm::Ed25519;

    validate_policy_move(&zone(), &current, &target).unwrap();
}

/// Verify that a move that changes the denial chain is allowed in place.
#[test]
fn policy_move_accepts_denial_chain_change_in_place() {
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
fn policy_move_rejects_key_layout_change() {
    let current = policy(1, "default");
    let mut target = policy(2, "split");
    target.split_keys = true;

    let error = validate_policy_move(&zone(), &current, &target).unwrap_err();

    assert!(error.to_string().contains("key layout"), "{}", error);
    assert!(
        error.to_string().contains("split KSK/ZSK keys"),
        "{}",
        error
    );
}

/// Verify that the key layout is still refused when the denial chain moves with it.
#[test]
fn policy_move_rejects_combined_key_layout_and_denial_change() {
    let current = policy(1, "default");
    let mut target = policy(2, "other");
    target.denial = DnssecDenial::Nsec3;
    target.split_keys = true;

    let error = validate_policy_move(&zone(), &current, &target).unwrap_err();

    assert!(error.to_string().contains("key layout"), "{}", error);
}
