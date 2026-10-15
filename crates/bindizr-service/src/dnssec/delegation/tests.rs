use bindizr_core::{
    dns::{Serial, SoaInterval, Ttl, name::ZoneName, query::DsRecord},
    model::{
        dnssec_key::{DnssecAlgorithm, DnssecKeyRole},
        dnssec_policy::PolicyId,
        zone::ZoneId,
    },
};

use super::*;
use crate::types::DsState;

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
        parent_ns_addrs: Some("192.0.2.1,192.0.2.2".to_string()),
        enabled: true,
        description: None,
        created_at: Utc::now(),
    }
}

/// Build a combined signing key fixture.
fn csk() -> DnssecKey {
    let now = Utc::now();
    DnssecKey::generate(
        &zone(),
        DnssecAlgorithm::EcdsaP256Sha256,
        DnssecKeyRole::Csk,
        DnssecKeyState::Active,
        now,
        now,
    )
    .unwrap()
}

/// The DS the parent would serve for `key`, in the digest type given.
fn ds_of(key: &DnssecKey, digest_type: u8) -> DsRecord {
    let apex = zone().name.to_wire_name().unwrap();
    DsRecord {
        key_tag: key.key_tag,
        digest_type,
        rdata: key
            .ds_rdata(&apex, digest_type)
            .unwrap()
            .as_bytes()
            .to_vec(),
    }
}

/// Build a record-group fixture from the supplied values.
fn record_set(records: Vec<DsRecord>) -> Option<DsRecordSet> {
    Some(DsRecordSet { records, ttl: 3600 })
}

/// Build a parent DS probe result from the supplied server answers.
fn parent(answers: Vec<Option<DsRecordSet>>) -> ParentDs {
    ParentDs {
        ns_addrs: vec!["192.0.2.1".to_string(), "192.0.2.2".to_string()],
        answers,
    }
}

/// Compute delegation information for a key and simulated parent answers.
fn delegation_response(
    key: &DnssecKey,
    answers: Vec<Option<DsRecordSet>>,
) -> DnssecDelegationResponse {
    build_delegation_response(&zone(), std::slice::from_ref(key), parent(answers)).unwrap()
}

/// Verify that promotion waits until every server serves the DS.
#[test]
fn promotion_waits_until_every_server_serves_the_ds() {
    let key = csk();
    let served = delegation_response(
        &key,
        vec![record_set(vec![ds_of(&key, 2)]), record_set(vec![])],
    );

    assert!(!served.keys[0].ds_published);
    assert!(
        delegation_response(&key, vec![record_set(vec![ds_of(&key, 2)]); 2]).keys[0].ds_published,
        "every server serving it should publish"
    );
}

/// Verify that one server still serving a DS is enough to block a disable.
#[test]
fn dnssec_disable_rejects_ds_remaining_on_any_parent_server() {
    // `disable` refuses on ds_key_tags, so the union is what it reads: dropping
    // signatures under a DS any resolver can still reach makes the zone bogus.
    let key = csk();
    let seen = delegation_response(&key, vec![None, record_set(vec![ds_of(&key, 2)])]);

    assert_eq!(seen.ds_key_tags, [key.key_tag]);
    assert_eq!(seen.ds_state, DsState::Published);
}

/// Verify that a parent serving nothing anywhere hides the delegation.
#[test]
fn delegation_reports_hidden_when_all_parents_answer_empty() {
    let key = csk();
    let hidden = delegation_response(&key, vec![None, None]);

    assert!(hidden.ds_key_tags.is_empty());
    assert_eq!(hidden.ds_state, DsState::Hidden);
    assert!(!hidden.keys[0].ds_published);
    assert!(!hidden.keys[0].ds_digest_unsupported);
}

/// Verify that a DS for another key does not publish this one.
#[test]
fn delegation_rejects_ds_for_another_key() {
    // Key tags are 16 bits and collide, so the whole RDATA is matched.
    let key = csk();
    let other = csk();
    let mut foreign = ds_of(&other, 2);
    foreign.key_tag = key.key_tag;

    let seen = delegation_response(&key, vec![record_set(vec![foreign]); 2]);

    assert!(!seen.keys[0].ds_published);
    assert_eq!(seen.ds_key_tags, [key.key_tag]);
}

/// Verify that a digest bindizr cannot compute leaves the match undecided.
#[test]
fn delegation_reports_unknown_match_for_unsupported_digest() {
    // RFC 8624, Section 3.3 retires GOST (3), so a parent serving only that
    // is not the same as a parent serving no DS at all.
    let key = csk();
    let gost = DsRecord {
        key_tag: key.key_tag,
        digest_type: 3,
        rdata: vec![0; 32],
    };

    let seen = delegation_response(&key, vec![record_set(vec![gost]); 2]);

    assert!(seen.keys[0].ds_digest_unsupported);
    assert!(!seen.keys[0].ds_published);
}

/// Verify that one server answering in a computable digest does not mask another.
#[test]
fn delegation_preserves_unknown_match_from_any_parent() {
    // A parent mid-rollout between digest types is undecided, not a match.
    let key = csk();
    let gost = DsRecord {
        key_tag: key.key_tag,
        digest_type: 3,
        rdata: vec![0; 32],
    };

    let seen = delegation_response(
        &key,
        vec![record_set(vec![ds_of(&key, 2)]), record_set(vec![gost])],
    );

    assert!(seen.keys[0].ds_digest_unsupported);
    assert!(!seen.keys[0].ds_published);
}

/// Verify that the TTL reported is the longest any server serves.
#[test]
fn delegation_returns_longest_parent_ttl() {
    let key = csk();
    let answers = vec![
        Some(DsRecordSet {
            records: vec![ds_of(&key, 2)],
            ttl: 300,
        }),
        Some(DsRecordSet {
            records: vec![ds_of(&key, 2)],
            ttl: 86400,
        }),
    ];

    assert_eq!(
        build_delegation_response(&zone(), &[key], parent(answers))
            .unwrap()
            .ds_ttl,
        Some(86400)
    );
}
