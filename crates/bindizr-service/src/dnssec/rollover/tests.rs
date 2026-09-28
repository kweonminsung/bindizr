use bindizr_core::{
    dns::{Serial, Ttl, name::ZoneName},
    model::{dnssec_policy::PolicyId, zone::ZoneId},
};

use super::*;
use crate::{
    error::ErrorCode,
    model::dnssec_policy::{DnssecDenial, DnssecPolicy},
};

/// Build the test zone or its DNS name.
fn zone() -> Zone {
    Zone {
        id: ZoneId::from(1),
        name: ZoneName::parse("example.com").unwrap(),
        mname: "ns1.example.com".to_string(),
        rname: "admin@example.com".to_string(),
        default_ttl: Ttl::from_secs(3600),
        serial: Serial::from(5),
        refresh: 300,
        retry: 60,
        expire: 3600000,
        minimum_ttl: Ttl::from_secs(900),
        dnssec_policy_id: Some(PolicyId::from(1)),
        parent_ns_addrs: None,
        enabled: true,
        description: None,
        created_at: Utc::now(),
    }
}

/// Build the policy the test zone signs under.
fn policy() -> DnssecPolicy {
    DnssecPolicy {
        id: PolicyId::from(1),
        name: "default".to_string(),
        algorithm: DnssecAlgorithm::EcdsaP256Sha256,
        denial: DnssecDenial::Nsec,
        split_keys: false,
        signature_validity_days: 14,
        signature_refresh_days: 5,
        zsk_lifetime_days: 0,
        created_at: Utc::now(),
    }
}

/// Build the signed zone a promotion reads: the test zone under its policy
/// with `keys`.
fn signed(keys: &[DnssecKey]) -> SignedZone {
    SignedZone {
        zone: zone(),
        policy: policy(),
        keys: keys.to_vec(),
    }
}

/// Build a DNSSEC key fixture in the requested lifecycle state.
fn key(id: i32, role: DnssecKeyRole, state: DnssecKeyState, eligible_in: i64) -> DnssecKey {
    let now = Utc::now();
    DnssecKey {
        id: DnssecKeyId::from(id),
        zone_id: ZoneId::from(1),
        role,
        algorithm: DnssecAlgorithm::EcdsaP256Sha256,
        key_tag: id,
        public_key: String::new(),
        private_key: String::new(),
        state,
        state_changed_at: now,
        eligible_at: now + Duration::hours(eligible_in),
        max_signed_ttl: Ttl::try_from(300).unwrap(),
        created_at: now,
    }
}

/// Verify that a published sep key past its hold down is promotable.
#[test]
fn a_published_sep_key_past_its_hold_down_is_promotable() {
    let keys = [
        key(1, DnssecKeyRole::Csk, DnssecKeyState::Active, -1),
        key(2, DnssecKeyRole::Csk, DnssecKeyState::Published, -1),
    ];

    assert_eq!(
        promotable_sep_key_ids(&signed(&keys), Holddown::Wait).unwrap(),
        [DnssecKeyId::from(2)]
    );
}

/// Verify that nothing published means no rollover to confirm.
#[test]
fn nothing_published_means_no_rollover_to_confirm() {
    let keys = [key(1, DnssecKeyRole::Csk, DnssecKeyState::Active, -1)];

    let error = promotable_sep_key_ids(&signed(&keys), Holddown::Wait).unwrap_err();

    assert_eq!(error.code(), ErrorCode::DnssecNoRolloverInProgress);
}

/// Verify that a ZSK rollover has no parent DS to confirm.
#[test]
fn a_zsk_rollover_has_no_parent_ds_to_confirm() {
    // Only a SEP key is answerable by `ds-seen`; the scheduler promotes a
    // ZSK once its publish hold-down passes.
    let keys = [
        key(1, DnssecKeyRole::Zsk, DnssecKeyState::Active, -1),
        key(2, DnssecKeyRole::Zsk, DnssecKeyState::Published, -1),
    ];

    let error = promotable_sep_key_ids(&signed(&keys), Holddown::Wait).unwrap_err();

    assert_eq!(error.code(), ErrorCode::InvalidInput);
    assert!(error.to_string().contains("ZSK"), "{}", error);
}

/// Verify that a hold down still running names the time to retry.
#[test]
fn a_hold_down_still_running_names_the_time_to_retry() {
    let keys = [
        key(1, DnssecKeyRole::Ksk, DnssecKeyState::Active, -1),
        key(2, DnssecKeyRole::Ksk, DnssecKeyState::Published, 1),
    ];

    let error = promotable_sep_key_ids(&signed(&keys), Holddown::Wait).unwrap_err();

    assert_eq!(error.code(), ErrorCode::InvalidInput);
    assert!(error.to_string().contains("retry after"), "{}", error);
}

/// Verify that skipping the hold down promotes anyway.
#[test]
fn skipping_the_hold_down_promotes_anyway() {
    let keys = [
        key(1, DnssecKeyRole::Ksk, DnssecKeyState::Active, -1),
        key(2, DnssecKeyRole::Ksk, DnssecKeyState::Published, 1),
    ];

    assert_eq!(
        promotable_sep_key_ids(&signed(&keys), Holddown::Skip).unwrap(),
        [DnssecKeyId::from(2)]
    );
}

/// Verify that the latest deadline among the published keys gates them all.
#[test]
fn the_latest_deadline_among_the_published_keys_gates_them_all() {
    // Each key carries its own deadline, so the one published last is what
    // `ds-seen` waits on for the whole set.
    let keys = [
        key(1, DnssecKeyRole::Ksk, DnssecKeyState::Published, -1),
        key(2, DnssecKeyRole::Ksk, DnssecKeyState::Published, 1),
    ];

    let error = promotable_sep_key_ids(&signed(&keys), Holddown::Wait).unwrap_err();

    assert_eq!(error.code(), ErrorCode::InvalidInput);
}

/// Verify that a retiring key waits out the signatures it made.
#[test]
fn a_retiring_key_waits_out_the_signatures_it_made() {
    let mut zsk = key(1, DnssecKeyRole::Zsk, DnssecKeyState::Active, 0);
    zsk.max_signed_ttl = Ttl::try_from(900).unwrap();

    // A ZSK has no DS at the parent, so only its signatures hold it back.
    assert_eq!(zsk.retirement_interval_secs(Some(86_400)), 900);
}

/// Verify that a retiring sep key also waits out the parents DS.
#[test]
fn a_retiring_sep_key_also_waits_out_the_parents_ds() {
    // Resolvers that cached the parent's DS record set before the replacement was
    // added hold it for its TTL, and it names only the key being removed.
    let mut csk = key(1, DnssecKeyRole::Csk, DnssecKeyState::Active, 0);
    csk.max_signed_ttl = Ttl::try_from(900).unwrap();

    assert_eq!(csk.retirement_interval_secs(Some(86_400)), 86_400);

    // A zone signed with a longer TTL than the parent's outlasts it.
    csk.max_signed_ttl = Ttl::try_from(604_800).unwrap();
    assert_eq!(csk.retirement_interval_secs(Some(86_400)), 604_800);

    // Nothing observed the parent, so only the signatures are known.
    csk.max_signed_ttl = Ttl::try_from(900).unwrap();
    assert_eq!(csk.retirement_interval_secs(None), 900);
}
