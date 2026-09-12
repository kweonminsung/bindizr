use bindizr_core::{
    dns::name::ZoneName,
    model::{dnssec_key::DnssecAlgorithm, dnssec_policy::DnssecDenial},
};

use super::*;

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
        created_at: Utc::now(),
    }
}

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
        rollover_publish_holddown_secs: 86_400,
        rollover_retire_holddown_secs: 172_800,
        created_at: Utc::now(),
    }
}

#[test]
fn a_move_that_only_changes_timings_is_allowed() {
    let current = policy(1, "default");
    let mut target = policy(2, "long-lived");
    target.signature_validity_days = 30;
    target.zsk_lifetime_days = 90;

    validate_policy_move(&zone(), &current, &target).unwrap();
}

#[test]
fn a_move_that_only_changes_the_algorithm_is_left_to_the_rollover() {
    let current = policy(1, "default");
    let mut target = policy(2, "ed25519");
    target.algorithm = DnssecAlgorithm::Ed25519;

    validate_policy_move(&zone(), &current, &target).unwrap();
}

#[test]
fn the_denial_chain_cannot_change_under_a_signed_zone() {
    let current = policy(1, "default");
    let mut target = policy(2, "nsec3");
    target.denial = DnssecDenial::Nsec3;

    let error = validate_policy_move(&zone(), &current, &target).unwrap_err();

    assert!(error.message.contains("denial mode"), "{}", error.message);
    assert!(error.message.contains("nsec3"), "{}", error.message);
}

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

#[test]
fn the_denial_chain_is_refused_before_the_key_layout() {
    // Both differ; the message names the denial mode, so an operator
    // fixing one thing at a time is not told the wrong one first.
    let current = policy(1, "default");
    let mut target = policy(2, "other");
    target.denial = DnssecDenial::Nsec3;
    target.split_keys = true;

    let error = validate_policy_move(&zone(), &current, &target).unwrap_err();

    assert!(error.message.contains("denial mode"), "{}", error.message);
}
