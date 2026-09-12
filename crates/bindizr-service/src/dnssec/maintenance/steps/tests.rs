use bindizr_core::model::dnssec_key::DnssecAlgorithm;
use chrono::Duration;

use super::*;

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

#[test]
fn a_retired_key_stays_while_its_replacement_is_only_published() {
    // A published key signs no zone data, so dropping the retired one
    // would leave the zone's signatures uncovered.
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
