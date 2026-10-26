use bindizr_core::dns::Ttl;
use bindizr_core::dns::dnssec::KeyTag;
use bindizr_core::model::dnssec_key::DnssecAlgorithm;
use chrono::Duration;

use super::*;

/// Build a DNSSEC key fixture in the requested lifecycle state.
fn key(id: i32, role: DnssecKeyRole, state: DnssecKeyState, eligible: DateTime<Utc>) -> DnssecKey {
    DnssecKey {
        id: DnssecKeyId::from(id),
        zone_id: ZoneId::from(1),
        role,
        algorithm: DnssecAlgorithm::EcdsaP256Sha256,
        key_tag: KeyTag::try_from(id).unwrap(),
        public_key: String::new(),
        private_key: String::new(),
        state,
        state_changed_at: eligible,
        eligible_at: eligible,
        max_signed_ttl: Ttl::try_from(300).unwrap(),
        created_at: eligible,
    }
}

/// Verify that a retired key goes once its replacement signs the zone.
#[test]
fn key_retirement_removes_key_after_replacement_signs() {
    let now = Utc::now();
    let keys = [
        key(
            1,
            DnssecKeyRole::Csk,
            DnssecKeyState::Retired,
            now - Duration::hours(1),
        ),
        key(
            2,
            DnssecKeyRole::Csk,
            DnssecKeyState::Active,
            now - Duration::hours(1),
        ),
    ];

    assert_eq!(removable_key_ids(&keys, now), [DnssecKeyId::from(1)]);
}

/// Verify that a retired key waits out its hold down.
#[test]
fn key_retirement_waits_for_hold_down() {
    // eligible_at is stamped at the transition, so caches may still be
    // validating with the key until it passes.
    let now = Utc::now();
    let keys = [
        key(
            1,
            DnssecKeyRole::Csk,
            DnssecKeyState::Retired,
            now + Duration::hours(1),
        ),
        key(
            2,
            DnssecKeyRole::Csk,
            DnssecKeyState::Active,
            now - Duration::hours(1),
        ),
    ];

    assert!(removable_key_ids(&keys, now).is_empty());
}

/// Verify that a retired key stays while its replacement is only published.
#[test]
fn key_retirement_preserves_key_when_replacement_is_only_published() {
    // Keeping this algorithm requires an active successor; publication alone
    // does not confirm that the replacement is ready to take over.
    let now = Utc::now();
    let keys = [
        key(
            1,
            DnssecKeyRole::Csk,
            DnssecKeyState::Retired,
            now - Duration::hours(1),
        ),
        key(
            2,
            DnssecKeyRole::Csk,
            DnssecKeyState::Published,
            now - Duration::hours(1),
        ),
    ];

    assert!(removable_key_ids(&keys, now).is_empty());
}

/// Verify that a KSK alone cannot keep its algorithm alive.
#[test]
fn algorithm_retirement_preserves_keys_without_signing_replacement() {
    // Only a CSK or ZSK signs zone data; an active KSK covers the DNSKEY
    // record set alone, so the retired ZSK's signatures have no successor.
    let now = Utc::now();
    let keys = [
        key(
            1,
            DnssecKeyRole::Zsk,
            DnssecKeyState::Retired,
            now - Duration::hours(1),
        ),
        key(
            2,
            DnssecKeyRole::Ksk,
            DnssecKeyState::Active,
            now - Duration::hours(1),
        ),
    ];

    assert!(removable_key_ids(&keys, now).is_empty());
}

/// Verify that an algorithm whose keys have all retired leaves together.
#[test]
fn algorithm_retirement_removes_all_retired_keys_together() {
    // RFC 6840, Section 5.11: an algorithm's DNSKEYs and its signatures
    // appear and disappear as one — the state an algorithm rollover leaves.
    let now = Utc::now();
    let mut keys = [
        key(
            1,
            DnssecKeyRole::Ksk,
            DnssecKeyState::Retired,
            now - Duration::hours(1),
        ),
        key(
            2,
            DnssecKeyRole::Zsk,
            DnssecKeyState::Retired,
            now - Duration::hours(1),
        ),
        key(
            3,
            DnssecKeyRole::Csk,
            DnssecKeyState::Active,
            now - Duration::hours(1),
        ),
    ];
    keys[2].algorithm = DnssecAlgorithm::Ed25519;

    assert_eq!(
        removable_key_ids(&keys, now),
        [DnssecKeyId::from(1), DnssecKeyId::from(2)]
    );
}

/// Verify that one key of a retiring algorithm still inside its hold down holds the rest.
#[test]
fn algorithm_retirement_waits_for_last_key_hold_down() {
    let now = Utc::now();
    let mut keys = [
        key(
            1,
            DnssecKeyRole::Ksk,
            DnssecKeyState::Retired,
            now - Duration::hours(1),
        ),
        key(
            2,
            DnssecKeyRole::Zsk,
            DnssecKeyState::Retired,
            now + Duration::hours(1),
        ),
        key(
            3,
            DnssecKeyRole::Csk,
            DnssecKeyState::Active,
            now - Duration::hours(1),
        ),
    ];
    keys[2].algorithm = DnssecAlgorithm::Ed25519;

    assert!(removable_key_ids(&keys, now).is_empty());
}
