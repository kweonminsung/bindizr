use serde_json::json;

use super::*;

/// Verify that `DnssecAlgorithm` has one spelling across `as_str`, serde, and `FromStr`.
#[test]
fn dnssec_algorithm_spells_itself_once() {
    for value in [
        DnssecAlgorithm::RsaSha256,
        DnssecAlgorithm::RsaSha512,
        DnssecAlgorithm::EcdsaP256Sha256,
        DnssecAlgorithm::EcdsaP384Sha384,
        DnssecAlgorithm::Ed25519,
        DnssecAlgorithm::Ed448,
    ] {
        assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
        assert_eq!(
            serde_json::from_value::<DnssecAlgorithm>(json!(value.as_str())).unwrap(),
            value
        );
        assert_eq!(value.as_str().parse::<DnssecAlgorithm>().unwrap(), value);
    }
}

/// Verify that `DnssecKeyRole` has one spelling across `as_str`, serde, and `FromStr`.
#[test]
fn dnssec_key_role_spells_itself_once() {
    for value in [DnssecKeyRole::Csk, DnssecKeyRole::Ksk, DnssecKeyRole::Zsk] {
        assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
        assert_eq!(
            serde_json::from_value::<DnssecKeyRole>(json!(value.as_str())).unwrap(),
            value
        );
        assert_eq!(value.as_str().parse::<DnssecKeyRole>().unwrap(), value);
    }
}

/// Verify that `DnssecKeyState` has one spelling across `as_str`, serde, and `FromStr`.
#[test]
fn dnssec_key_state_spells_itself_once() {
    for value in [
        DnssecKeyState::Published,
        DnssecKeyState::Active,
        DnssecKeyState::Retired,
    ] {
        assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
        assert_eq!(
            serde_json::from_value::<DnssecKeyState>(json!(value.as_str())).unwrap(),
            value
        );
        assert_eq!(value.as_str().parse::<DnssecKeyState>().unwrap(), value);
    }
}

/// Build an active key of `role` that signed record sets of up to 900 seconds.
fn active_key(role: DnssecKeyRole) -> DnssecKey {
    let now = Utc::now();
    DnssecKey {
        id: DnssecKeyId::from(1),
        zone_id: ZoneId::from(1),
        role,
        algorithm: DnssecAlgorithm::EcdsaP256Sha256,
        key_tag: KeyTag::try_from(1).unwrap(),
        public_key: String::new(),
        private_key: String::new(),
        state: DnssecKeyState::Active,
        state_changed_at: now,
        eligible_at: now,
        max_signed_ttl: Ttl::from_secs(900),
        created_at: now,
    }
}

/// Verify that a retiring key waits out the signatures it made.
#[test]
fn retiring_key_waits_for_signature_expiration() {
    let zsk = active_key(DnssecKeyRole::Zsk);

    // A ZSK has no DS at the parent, so only its signatures hold it back.
    assert_eq!(
        zsk.retirement_interval_secs(Some(Ttl::from_secs(86400)), 0),
        900
    );

    // Propagation is added whole: a secondary may need the SOA refresh to catch up.
    assert_eq!(
        zsk.retirement_interval_secs(Some(Ttl::from_secs(86400)), 300),
        1200
    );
}

/// Verify that a retiring sep key also waits out the parents DS.
#[test]
fn retiring_sep_key_waits_for_parent_ds_expiration() {
    // Resolvers that cached the parent's DS record set before the replacement was
    // added hold it for its TTL, and it names only the key being removed.
    let mut csk = active_key(DnssecKeyRole::Csk);

    assert_eq!(
        csk.retirement_interval_secs(Some(Ttl::from_secs(86400)), 0),
        86400
    );

    // A zone signed with a longer TTL than the parent's outlasts it.
    csk.max_signed_ttl = Ttl::from_secs(604_800);

    assert_eq!(
        csk.retirement_interval_secs(Some(Ttl::from_secs(86400)), 0),
        604_800
    );

    // Nothing observed the parent, so only the signatures are known.
    csk.max_signed_ttl = Ttl::from_secs(900);

    assert_eq!(csk.retirement_interval_secs(None, 0), 900);
}
