use bindizr_core::{
    dns::{dnssec::generate_key, name::ZoneName, query::DsRr},
    model::dnssec_key::{DnssecAlgorithm, DnssecKeyRole},
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
        parent_ns_addrs: Some("192.0.2.1,192.0.2.2".to_string()),
        enabled: true,
        description: None,
        created_at: Utc::now(),
    }
}

fn csk() -> DnssecKey {
    let now = Utc::now();
    generate_key(
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
fn ds_of(key: &DnssecKey, digest_type: u8) -> DsRr {
    let apex = to_wire_name(zone().name.to_wire()).unwrap();
    DsRr {
        key_tag: key.key_tag as u16,
        digest_type,
        rdata: ds_rdata_for(key, &apex, digest_type)
            .unwrap()
            .as_bytes()
            .to_vec(),
    }
}

fn rrset(records: Vec<DsRr>) -> Option<DsRrset> {
    Some(DsRrset { records, ttl: 3600 })
}

fn parent(answers: Vec<Option<DsRrset>>) -> ParentDs {
    ParentDs {
        ns_addrs: vec!["192.0.2.1".to_string(), "192.0.2.2".to_string()],
        answers,
    }
}

fn info(key: &DnssecKey, answers: Vec<Option<DsRrset>>) -> DnssecDelegationInfo {
    to_delegation_info(&zone(), std::slice::from_ref(key), parent(answers)).unwrap()
}

#[test]
fn promotion_waits_until_every_server_serves_the_ds() {
    let key = csk();
    let served = info(&key, vec![rrset(vec![ds_of(&key, 2)]), rrset(vec![])]);

    assert!(!served.keys[0].ds_published);
    assert!(
        info(&key, vec![rrset(vec![ds_of(&key, 2)]); 2]).keys[0].ds_published,
        "every server serving it should publish"
    );
}

#[test]
fn one_server_still_serving_a_ds_is_enough_to_block_a_disable() {
    // `disable` refuses on ds_key_tags, so the union is what it reads: dropping
    // signatures under a DS any resolver can still reach makes the zone bogus.
    let key = csk();
    let seen = info(&key, vec![None, rrset(vec![ds_of(&key, 2)])]);

    assert_eq!(seen.ds_key_tags, [key.key_tag as u16]);
    assert_eq!(seen.ds_state, "published");
}

#[test]
fn a_parent_serving_nothing_anywhere_hides_the_delegation() {
    let key = csk();
    let hidden = info(&key, vec![None, None]);

    assert!(hidden.ds_key_tags.is_empty());
    assert_eq!(hidden.ds_state, "hidden");
    assert!(!hidden.keys[0].ds_published);
    assert!(!hidden.keys[0].ds_digest_unsupported);
}

#[test]
fn a_ds_for_another_key_does_not_publish_this_one() {
    // Key tags are 16 bits and collide, so the whole RDATA is matched.
    let key = csk();
    let other = csk();
    let mut foreign = ds_of(&other, 2);
    foreign.key_tag = key.key_tag as u16;

    let seen = info(&key, vec![rrset(vec![foreign]); 2]);

    assert!(!seen.keys[0].ds_published);
    assert_eq!(seen.ds_key_tags, [key.key_tag as u16]);
}

#[test]
fn a_digest_bindizr_cannot_compute_leaves_the_match_undecided() {
    // RFC 8624, Section 3.3 retires GOST (3), so a parent serving only that
    // is not the same as a parent serving no DS at all.
    let key = csk();
    let gost = DsRr {
        key_tag: key.key_tag as u16,
        digest_type: 3,
        rdata: vec![0; 32],
    };

    let seen = info(&key, vec![rrset(vec![gost]); 2]);

    assert!(seen.keys[0].ds_digest_unsupported);
    assert!(!seen.keys[0].ds_published);
}

#[test]
fn one_server_answering_in_a_computable_digest_does_not_mask_another() {
    // A parent mid-rollout between digest types is undecided, not a match.
    let key = csk();
    let gost = DsRr {
        key_tag: key.key_tag as u16,
        digest_type: 3,
        rdata: vec![0; 32],
    };

    let seen = info(&key, vec![rrset(vec![ds_of(&key, 2)]), rrset(vec![gost])]);

    assert!(seen.keys[0].ds_digest_unsupported);
    assert!(!seen.keys[0].ds_published);
}

#[test]
fn the_ttl_reported_is_the_longest_any_server_serves() {
    let key = csk();
    let answers = vec![
        Some(DsRrset {
            records: vec![ds_of(&key, 2)],
            ttl: 300,
        }),
        Some(DsRrset {
            records: vec![ds_of(&key, 2)],
            ttl: 86400,
        }),
    ];

    assert_eq!(
        to_delegation_info(&zone(), &[key], parent(answers))
            .unwrap()
            .ds_ttl,
        Some(86400)
    );
}
