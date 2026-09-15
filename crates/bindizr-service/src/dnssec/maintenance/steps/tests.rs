use bindizr_core::model::dnssec_key::DnssecAlgorithm;
use chrono::Duration;

use super::*;

/// Build a DNSSEC key fixture in the requested lifecycle state.
fn key(id: i32, role: DnssecKeyRole, state: DnssecKeyState, eligible: DateTime<Utc>) -> DnssecKey {
    DnssecKey {
        id,
        zone_id: 1,
        role,
        algorithm: DnssecAlgorithm::EcdsaP256Sha256,
        key_tag: id,
        public_key: String::new(),
        private_key: String::new(),
        state,
        state_changed_at: eligible,
        eligible_at: eligible,
        max_signed_ttl: 300,
        created_at: eligible,
    }
}

/// Verify that a retired key goes once its replacement signs the zone.
#[test]
fn a_retired_key_goes_once_its_replacement_signs_the_zone() {
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

    assert_eq!(removable_key_ids(&keys, now), [1]);
}

/// Verify that a retired key waits out its hold down.
#[test]
fn a_retired_key_waits_out_its_hold_down() {
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
fn a_retired_key_stays_while_its_replacement_is_only_published() {
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
fn a_ksk_alone_cannot_keep_its_algorithm_alive() {
    // Only a CSK or ZSK signs zone data; an active KSK covers the DNSKEY
    // RRset alone, so the retired ZSK's signatures have no successor.
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
fn an_algorithm_whose_keys_have_all_retired_leaves_together() {
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

    assert_eq!(removable_key_ids(&keys, now), [1, 2]);
}

/// Verify that one key of a retiring algorithm still inside its hold down holds the rest.
#[test]
fn one_key_of_a_retiring_algorithm_still_inside_its_hold_down_holds_the_rest() {
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
