use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};

use super::{SignedViewDiff, SignedViewParams};
use crate::{
    dns::{
        dnssec::generate_key,
        name::{OwnerName, ZoneName},
    },
    model::{
        dnssec_key::{DnssecAlgorithm, DnssecKey, DnssecKeyRole, DnssecKeyState},
        dnssec_record::{DnssecRecord, DnssecRecordType},
        record::{Record, RecordType},
        zone::{DnssecDenial, Zone},
    },
};

fn test_zone() -> Zone {
    Zone {
        id: 1,
        name: ZoneName::parse("example.com").unwrap(),
        mname: "ns1.example.com".to_string(),
        rname: "admin@example.com".to_string(),
        default_ttl: 3600,
        serial: 5,
        refresh: 300,
        retry: 60,
        expire: 3600000,
        minimum_ttl: 900,
        dnssec_denial: DnssecDenial::Nsec,
        created_at: Utc::now(),
    }
}

fn test_record(name: &str, record_type: RecordType, value: &str, ttl: i32) -> Record {
    let zone = ZoneName::parse("example.com").unwrap();
    Record {
        id: 0,
        name: if name == "@" {
            OwnerName::apex()
        } else {
            OwnerName::parse_in_zone(name, &zone).unwrap()
        },
        record_type,
        value: value.to_string(),
        ttl,
        priority: None,
        created_at: Utc::now(),
        zone_id: 1,
    }
}

fn test_key(zone: &Zone, id: i32, role: DnssecKeyRole, state: DnssecKeyState) -> DnssecKey {
    let mut key = generate_key(
        zone,
        DnssecAlgorithm::EcdsaP256Sha256,
        role,
        state,
        fixed_now(),
        fixed_now(),
    )
    .unwrap();
    key.id = id;
    key
}

fn fixed_now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-08-18T00:00:00Z")
        .unwrap()
        .to_utc()
}

struct ComputeArgs<'a> {
    zone: &'a Zone,
    records: &'a [Record],
    keys: &'a [DnssecKey],
    prev: &'a [DnssecRecord],
    denial: DnssecDenial,
    new_serial: i32,
    expiration: DateTime<Utc>,
    /// `0` pins every RRset to `expiration`; the spread has its own test.
    expiration_jitter_secs: i64,
    force: bool,
}

fn compute(args: ComputeArgs<'_>) -> SignedViewDiff {
    let now = fixed_now();
    SignedViewParams {
        zone: args.zone,
        new_serial: args.new_serial,
        records: args.records,
        keys: args.keys,
        prev: args.prev,
        denial: args.denial,
        now,
        inception: now - Duration::hours(1),
        expiration: args.expiration,
        expiration_jitter_secs: args.expiration_jitter_secs,
        refresh_secs: 5 * 86_400,
        force: args.force,
        withdraw_parent_ds: false,
    }
    .compute()
    .unwrap()
}

fn default_expiration() -> DateTime<Utc> {
    fixed_now() + Duration::days(14)
}

/// Stored form of a computed plane: rows get distinct ids like the database
/// would assign.
fn as_stored(rows: &[DnssecRecord]) -> Vec<DnssecRecord> {
    rows.iter()
        .enumerate()
        .map(|(index, row)| DnssecRecord {
            id: index as i32 + 1,
            ..row.clone()
        })
        .collect()
}

fn rows_of_type(rows: &[DnssecRecord], record_type: DnssecRecordType) -> Vec<&DnssecRecord> {
    rows.iter()
        .filter(|row| row.record_type == record_type)
        .collect()
}

fn rrsigs_covering<'a>(
    rows: &'a [DnssecRecord],
    owner: &OwnerName,
    covered: i32,
) -> Vec<&'a DnssecRecord> {
    rows.iter()
        .filter(|row| {
            row.record_type == DnssecRecordType::Rrsig
                && row.covered_record_type == Some(covered)
                && row.name == *owner
        })
        .collect()
}

const RECORD_TYPE_SOA: i32 = 6;
const RECORD_TYPE_NS: i32 = 2;
const RECORD_TYPE_A: i32 = 1;
const RECORD_TYPE_DS: i32 = 43;

#[test]
fn expirations_spread_across_the_jitter_window() {
    let zone = test_zone();
    let keys = [test_key(
        &zone,
        1,
        DnssecKeyRole::Csk,
        DnssecKeyState::Active,
    )];
    let records: Vec<Record> = (0..12)
        .map(|index| {
            test_record(
                &format!("host{index}"),
                RecordType::A,
                &format!("192.0.2.{index}"),
                300,
            )
        })
        .collect();
    let window = 21_600;

    let diff = compute(ComputeArgs {
        zone: &zone,
        records: &records,
        keys: &keys,
        prev: &[],
        denial: DnssecDenial::Nsec,
        new_serial: 2,
        expiration: default_expiration(),
        expiration_jitter_secs: window,
        force: false,
    });

    let expirations: BTreeSet<DateTime<Utc>> = rows_of_type(&diff.added, DnssecRecordType::Rrsig)
        .iter()
        .filter_map(|row| row.expires_at)
        .collect();
    assert!(
        expirations.len() > 1,
        "one pass would come due for every RRset at once: {expirations:?}"
    );
    let earliest = *expirations.iter().next().expect("signatures were emitted");
    let latest = *expirations
        .iter()
        .next_back()
        .expect("signatures were emitted");
    assert!(latest <= default_expiration());
    assert!(earliest > default_expiration() - Duration::seconds(window));
}

#[test]
fn initial_signing_emits_key_rrsets_nsec_chain_and_rrsigs() {
    let zone = test_zone();
    let keys = [test_key(
        &zone,
        1,
        DnssecKeyRole::Csk,
        DnssecKeyState::Active,
    )];
    let records = [
        test_record("@", RecordType::NS, "ns1.example.com", 3600),
        test_record("www", RecordType::A, "192.0.2.10", 300),
    ];

    let diff = compute(ComputeArgs {
        zone: &zone,
        records: &records,
        keys: &keys,
        prev: &[],
        denial: DnssecDenial::Nsec,
        new_serial: 6,
        expiration: default_expiration(),
        expiration_jitter_secs: 0,
        force: false,
    });

    assert!(diff.removed.is_empty());
    assert_eq!(rows_of_type(&diff.added, DnssecRecordType::Dnskey).len(), 1);
    // The CSK wants a parent DS, so it is advertised via CDS/CDNSKEY (RFC 7344).
    assert_eq!(rows_of_type(&diff.added, DnssecRecordType::Cds).len(), 1);
    assert_eq!(
        rows_of_type(&diff.added, DnssecRecordType::Cdnskey).len(),
        1
    );

    // One NSEC per authoritative name, chained apex → www → apex.
    let nsecs = rows_of_type(&diff.added, DnssecRecordType::Nsec);
    assert_eq!(nsecs.len(), 2);
    let apex_nsec = nsecs.iter().find(|row| row.name.is_apex()).unwrap();
    let www_wire = b"\x03www\x07example\x03com\x00";
    let apex_rdata = apex_nsec.rdata.as_bytes();
    assert!(
        apex_rdata.starts_with(www_wire),
        "apex NSEC must point at www"
    );
    let www_nsec = nsecs.iter().find(|row| !row.name.is_apex()).unwrap();
    let apex_wire = b"\x07example\x03com\x00";
    assert!(
        www_nsec.rdata.as_bytes().starts_with(apex_wire),
        "last NSEC must wrap around to the apex"
    );
    // NSEC TTL is min(SOA TTL, SOA MINIMUM) per RFC 9077.
    assert!(nsecs.iter().all(|row| row.ttl == 900));

    // RRSIGs: SOA, DNSKEY, CDS, CDNSKEY, apex NS, apex NSEC, www A, www NSEC.
    let rrsigs = rows_of_type(&diff.added, DnssecRecordType::Rrsig);
    assert_eq!(rrsigs.len(), 8);
    let apex = OwnerName::apex();
    let www = OwnerName::parse_in_zone("www", &zone.name).unwrap();
    assert_eq!(
        rrsigs_covering(&diff.added, &apex, RECORD_TYPE_SOA).len(),
        1
    );
    assert_eq!(
        rrsigs_covering(
            &diff.added,
            &apex,
            DnssecRecordType::Dnskey.wire_type() as i32
        )
        .len(),
        1
    );
    assert_eq!(
        rrsigs_covering(&diff.added, &apex, DnssecRecordType::Cds.wire_type() as i32).len(),
        1
    );
    assert_eq!(rrsigs_covering(&diff.added, &apex, RECORD_TYPE_NS).len(), 1);
    assert_eq!(rrsigs_covering(&diff.added, &www, RECORD_TYPE_A).len(), 1);
    assert!(rrsigs.iter().all(|row| row.expires_at.is_some()));
    assert!(rrsigs.iter().all(|row| row.rrset_digest.is_some()));
}

#[test]
fn nsec3_mode_builds_hashed_chain_with_nsec3param() {
    let zone = test_zone();
    let keys = [test_key(
        &zone,
        1,
        DnssecKeyRole::Csk,
        DnssecKeyState::Active,
    )];
    let records = [
        test_record("@", RecordType::NS, "ns1.example.com", 3600),
        test_record("www", RecordType::A, "192.0.2.10", 300),
    ];

    let diff = compute(ComputeArgs {
        zone: &zone,
        records: &records,
        keys: &keys,
        prev: &[],
        denial: DnssecDenial::Nsec3,
        new_serial: 6,
        expiration: default_expiration(),
        expiration_jitter_secs: 0,
        force: false,
    });

    assert!(rows_of_type(&diff.added, DnssecRecordType::Nsec).is_empty());
    let params = rows_of_type(&diff.added, DnssecRecordType::Nsec3param);
    assert_eq!(params.len(), 1);
    assert!(params[0].name.is_apex());
    // RFC 9276 parameters: SHA-1 (1), flags 0, iterations 0, empty salt.
    assert_eq!(params[0].rdata.as_bytes(), [1, 0, 0, 0, 0]);

    // One NSEC3 per authoritative name, at a hashed (base32) owner label.
    let nsec3s = rows_of_type(&diff.added, DnssecRecordType::Nsec3);
    assert_eq!(nsec3s.len(), 2);
    assert!(nsec3s.iter().all(|row| !row.name.is_apex()));

    // Every NSEC3 and the NSEC3PARAM RRset is signed.
    for row in nsec3s {
        assert_eq!(
            rrsigs_covering(
                &diff.added,
                &row.name,
                DnssecRecordType::Nsec3.wire_type() as i32
            )
            .len(),
            1
        );
    }
    assert_eq!(
        rrsigs_covering(
            &diff.added,
            &OwnerName::apex(),
            DnssecRecordType::Nsec3param.wire_type() as i32
        )
        .len(),
        1
    );
}

#[test]
fn published_key_cosigns_key_rrsets_but_not_zone_data() {
    let zone = test_zone();
    let keys = [
        test_key(&zone, 1, DnssecKeyRole::Csk, DnssecKeyState::Active),
        test_key(&zone, 2, DnssecKeyRole::Csk, DnssecKeyState::Published),
    ];
    let records = [
        test_record("@", RecordType::NS, "ns1.example.com", 3600),
        test_record("www", RecordType::A, "192.0.2.10", 300),
    ];

    let diff = compute(ComputeArgs {
        zone: &zone,
        records: &records,
        keys: &keys,
        prev: &[],
        denial: DnssecDenial::Nsec,
        new_serial: 6,
        expiration: default_expiration(),
        expiration_jitter_secs: 0,
        force: false,
    });

    let apex = OwnerName::apex();
    let www = OwnerName::parse_in_zone("www", &zone.name).unwrap();
    // Both keys are published and advertised to the parent (double-DS).
    assert_eq!(rows_of_type(&diff.added, DnssecRecordType::Dnskey).len(), 2);
    assert_eq!(rows_of_type(&diff.added, DnssecRecordType::Cds).len(), 2);
    // Both SEP keys sign the DNSKEY RRset — a validator may arrive via either
    // DS — but only the active key signs zone data.
    assert_eq!(
        rrsigs_covering(
            &diff.added,
            &apex,
            DnssecRecordType::Dnskey.wire_type() as i32
        )
        .len(),
        2
    );
    assert_eq!(rrsigs_covering(&diff.added, &www, RECORD_TYPE_A).len(), 1);
    assert_eq!(
        rrsigs_covering(&diff.added, &apex, RECORD_TYPE_SOA).len(),
        1
    );
}

#[test]
fn retired_key_stays_published_but_leaves_the_cds_set() {
    let zone = test_zone();
    let keys = [
        test_key(&zone, 1, DnssecKeyRole::Csk, DnssecKeyState::Active),
        test_key(&zone, 2, DnssecKeyRole::Csk, DnssecKeyState::Retired),
    ];
    let records = [test_record("@", RecordType::NS, "ns1.example.com", 3600)];

    let diff = compute(ComputeArgs {
        zone: &zone,
        records: &records,
        keys: &keys,
        prev: &[],
        denial: DnssecDenial::Nsec,
        new_serial: 6,
        expiration: default_expiration(),
        expiration_jitter_secs: 0,
        force: false,
    });

    let apex = OwnerName::apex();
    // Still in the DNSKEY RRset (cached signatures and a possibly lingering
    // old DS need it) and still co-signing that RRset...
    assert_eq!(rows_of_type(&diff.added, DnssecRecordType::Dnskey).len(), 2);
    assert_eq!(
        rrsigs_covering(
            &diff.added,
            &apex,
            DnssecRecordType::Dnskey.wire_type() as i32
        )
        .len(),
        2
    );
    // ...but no longer advertised to the parent: its DS should be dropped.
    assert_eq!(rows_of_type(&diff.added, DnssecRecordType::Cds).len(), 1);
    assert_eq!(
        rows_of_type(&diff.added, DnssecRecordType::Cdnskey).len(),
        1
    );
    // And it signs no zone data.
    assert_eq!(rrsigs_covering(&diff.added, &apex, RECORD_TYPE_NS).len(), 1);
}

#[test]
fn split_keys_partition_key_rrsets_from_zone_data() {
    let zone = test_zone();
    let keys = [
        test_key(&zone, 1, DnssecKeyRole::Ksk, DnssecKeyState::Active),
        test_key(&zone, 2, DnssecKeyRole::Zsk, DnssecKeyState::Active),
    ];
    let records = [
        test_record("@", RecordType::NS, "ns1.example.com", 3600),
        test_record("www", RecordType::A, "192.0.2.10", 300),
    ];

    let diff = compute(ComputeArgs {
        zone: &zone,
        records: &records,
        keys: &keys,
        prev: &[],
        denial: DnssecDenial::Nsec,
        new_serial: 6,
        expiration: default_expiration(),
        expiration_jitter_secs: 0,
        force: false,
    });

    let apex = OwnerName::apex();
    let www = OwnerName::parse_in_zone("www", &zone.name).unwrap();
    assert_eq!(rows_of_type(&diff.added, DnssecRecordType::Dnskey).len(), 2);
    // Only the KSK is in the parent DS set and signs the key RRsets
    // (RFC 7344, Section 4.1); only the ZSK signs zone data.
    assert_eq!(rows_of_type(&diff.added, DnssecRecordType::Cds).len(), 1);
    assert_eq!(
        rrsigs_covering(
            &diff.added,
            &apex,
            DnssecRecordType::Dnskey.wire_type() as i32
        )
        .len(),
        1
    );
    assert_eq!(
        rrsigs_covering(&diff.added, &apex, DnssecRecordType::Cds.wire_type() as i32).len(),
        1
    );
    assert_eq!(
        rrsigs_covering(&diff.added, &apex, RECORD_TYPE_SOA).len(),
        1
    );
    assert_eq!(rrsigs_covering(&diff.added, &www, RECORD_TYPE_A).len(), 1);
}

#[test]
fn recompute_against_stored_plane_is_empty() {
    let zone = test_zone();
    let keys = [test_key(
        &zone,
        1,
        DnssecKeyRole::Csk,
        DnssecKeyState::Active,
    )];
    let records = [
        test_record("@", RecordType::NS, "ns1.example.com", 3600),
        test_record("www", RecordType::A, "192.0.2.10", 300),
    ];

    let initial = compute(ComputeArgs {
        zone: &zone,
        records: &records,
        keys: &keys,
        prev: &[],
        denial: DnssecDenial::Nsec,
        new_serial: 6,
        expiration: default_expiration(),
        expiration_jitter_secs: 0,
        force: false,
    });
    let stored = as_stored(&initial.added);

    // Same serial: the signed content, SOA included, is unchanged.
    let diff = compute(ComputeArgs {
        zone: &zone,
        records: &records,
        keys: &keys,
        prev: &stored,
        denial: DnssecDenial::Nsec,
        new_serial: 6,
        expiration: default_expiration(),
        expiration_jitter_secs: 0,
        force: false,
    });

    assert!(diff.added.is_empty(), "added: {:?}", diff.added);
    assert!(diff.removed.is_empty(), "removed: {:?}", diff.removed);
}

#[test]
fn record_change_reuses_unaffected_signatures() {
    let zone = test_zone();
    let keys = [test_key(
        &zone,
        1,
        DnssecKeyRole::Csk,
        DnssecKeyState::Active,
    )];
    let records = [
        test_record("@", RecordType::NS, "ns1.example.com", 3600),
        test_record("www", RecordType::A, "192.0.2.10", 300),
    ];

    let initial = compute(ComputeArgs {
        zone: &zone,
        records: &records,
        keys: &keys,
        prev: &[],
        denial: DnssecDenial::Nsec,
        new_serial: 6,
        expiration: default_expiration(),
        expiration_jitter_secs: 0,
        force: false,
    });
    let stored = as_stored(&initial.added);

    let mut records_after: Vec<Record> = records.to_vec();
    records_after.push(test_record("zzz", RecordType::A, "192.0.2.11", 300));

    let diff = compute(ComputeArgs {
        zone: &zone,
        records: &records_after,
        keys: &keys,
        prev: &stored,
        denial: DnssecDenial::Nsec,
        new_serial: 7,
        expiration: default_expiration(),
        expiration_jitter_secs: 0,
        force: false,
    });

    let apex = OwnerName::apex();
    let www = OwnerName::parse_in_zone("www", &zone.name).unwrap();
    let zzz = OwnerName::parse_in_zone("zzz", &zone.name).unwrap();

    // Untouched RRsets keep their signatures: neither the DNSKEY nor the
    // www A RRSIG appears on either side of the diff.
    assert!(
        rrsigs_covering(
            &diff.added,
            &apex,
            DnssecRecordType::Dnskey.wire_type() as i32
        )
        .is_empty()
    );
    assert!(
        rrsigs_covering(
            &diff.removed,
            &apex,
            DnssecRecordType::Dnskey.wire_type() as i32
        )
        .is_empty()
    );
    assert!(rrsigs_covering(&diff.added, &www, RECORD_TYPE_A).is_empty());
    assert!(rrsigs_covering(&diff.removed, &www, RECORD_TYPE_A).is_empty());

    // The SOA rdata carries the new serial, so its signature is replaced.
    assert_eq!(
        rrsigs_covering(&diff.added, &apex, RECORD_TYPE_SOA).len(),
        1
    );
    assert_eq!(
        rrsigs_covering(&diff.removed, &apex, RECORD_TYPE_SOA).len(),
        1
    );

    // The new name gets its records; the chain splices it in after www.
    assert_eq!(rrsigs_covering(&diff.added, &zzz, RECORD_TYPE_A).len(), 1);
    assert!(
        diff.added
            .iter()
            .any(|row| row.record_type == DnssecRecordType::Nsec && row.name == zzz)
    );
    assert!(
        diff.removed
            .iter()
            .any(|row| row.record_type == DnssecRecordType::Nsec && row.name == www)
    );
}

#[test]
fn signature_inside_refresh_window_is_resigned() {
    let zone = test_zone();
    let keys = [test_key(
        &zone,
        1,
        DnssecKeyRole::Csk,
        DnssecKeyState::Active,
    )];
    let records = [test_record("@", RecordType::NS, "ns1.example.com", 3600)];

    // Sign with an expiration already inside the 5-day refresh window.
    let initial = compute(ComputeArgs {
        zone: &zone,
        records: &records,
        keys: &keys,
        prev: &[],
        denial: DnssecDenial::Nsec,
        new_serial: 6,
        expiration: fixed_now() + Duration::days(2),
        expiration_jitter_secs: 0,
        force: false,
    });
    let stored = as_stored(&initial.added);
    let stored_rrsigs = rows_of_type(&stored, DnssecRecordType::Rrsig).len();

    let diff = compute(ComputeArgs {
        zone: &zone,
        records: &records,
        keys: &keys,
        prev: &stored,
        denial: DnssecDenial::Nsec,
        new_serial: 6,
        expiration: default_expiration(),
        expiration_jitter_secs: 0,
        force: false,
    });

    // Content is unchanged, so only signatures move — every one of them.
    assert_eq!(
        rows_of_type(&diff.removed, DnssecRecordType::Rrsig).len(),
        stored_rrsigs
    );
    assert_eq!(
        rows_of_type(&diff.added, DnssecRecordType::Rrsig).len(),
        stored_rrsigs
    );
    assert!(rows_of_type(&diff.added, DnssecRecordType::Nsec).is_empty());
    assert!(rows_of_type(&diff.removed, DnssecRecordType::Dnskey).is_empty());
}

#[test]
fn delegation_ns_and_glue_are_unsigned() {
    let zone = test_zone();
    let keys = [test_key(
        &zone,
        1,
        DnssecKeyRole::Csk,
        DnssecKeyState::Active,
    )];
    let records = [
        test_record("@", RecordType::NS, "ns1.example.com", 3600),
        test_record("sub", RecordType::NS, "ns.sub.example.com", 3600),
        test_record(
            "sub",
            RecordType::DS,
            "12345 13 2 4B9B6B073EDD97FE1A7B19871EE93BE250E49B2D9466E661A22C74C426ACE383",
            3600,
        ),
        test_record("sub", RecordType::A, "192.0.2.53", 3600),
        test_record("ns.sub", RecordType::A, "192.0.2.53", 3600),
        test_record("www", RecordType::A, "192.0.2.10", 300),
    ];

    let diff = compute(ComputeArgs {
        zone: &zone,
        records: &records,
        keys: &keys,
        prev: &[],
        denial: DnssecDenial::Nsec,
        new_serial: 6,
        expiration: default_expiration(),
        expiration_jitter_secs: 0,
        force: false,
    });

    let sub = OwnerName::parse_in_zone("sub", &zone.name).unwrap();
    let glue = OwnerName::parse_in_zone("ns.sub", &zone.name).unwrap();

    // RFC 4035, Section 2.2: the delegation NS RRset and glue — the A at the
    // cut owner included — are not signed, and glue owns no NSEC; the
    // delegation point itself stays in the chain.
    assert!(rrsigs_covering(&diff.added, &sub, RECORD_TYPE_NS).is_empty());
    assert!(rrsigs_covering(&diff.added, &sub, RECORD_TYPE_A).is_empty());
    assert!(rrsigs_covering(&diff.added, &glue, RECORD_TYPE_A).is_empty());
    // The DS RRset at the cut is the parent's authoritative data (RFC 4035,
    // Section 2.4), unlike the NS beside it.
    assert_eq!(rrsigs_covering(&diff.added, &sub, RECORD_TYPE_DS).len(), 1);
    assert!(
        !diff
            .added
            .iter()
            .any(|row| row.record_type == DnssecRecordType::Nsec && row.name == glue)
    );
    assert!(
        diff.added
            .iter()
            .any(|row| row.record_type == DnssecRecordType::Nsec && row.name == sub)
    );
}

#[test]
fn force_resigns_every_rrset() {
    let zone = test_zone();
    let keys = [test_key(
        &zone,
        1,
        DnssecKeyRole::Csk,
        DnssecKeyState::Active,
    )];
    let records = [test_record("@", RecordType::NS, "ns1.example.com", 3600)];

    let initial = compute(ComputeArgs {
        zone: &zone,
        records: &records,
        keys: &keys,
        prev: &[],
        denial: DnssecDenial::Nsec,
        new_serial: 6,
        expiration: default_expiration(),
        expiration_jitter_secs: 0,
        force: false,
    });
    let stored = as_stored(&initial.added);
    let stored_rrsigs = rows_of_type(&stored, DnssecRecordType::Rrsig).len();

    let diff = compute(ComputeArgs {
        zone: &zone,
        records: &records,
        keys: &keys,
        prev: &stored,
        denial: DnssecDenial::Nsec,
        new_serial: 6,
        expiration: default_expiration() + Duration::days(1),
        expiration_jitter_secs: 0,
        force: true,
    });

    assert_eq!(
        rows_of_type(&diff.added, DnssecRecordType::Rrsig).len(),
        stored_rrsigs
    );
    assert_eq!(
        rows_of_type(&diff.removed, DnssecRecordType::Rrsig).len(),
        stored_rrsigs
    );
}

#[test]
fn mixed_ttl_rrset_signs_at_the_minimum() {
    let zone = test_zone();
    let keys = [test_key(
        &zone,
        1,
        DnssecKeyRole::Csk,
        DnssecKeyState::Active,
    )];
    let records = [
        test_record("@", RecordType::NS, "ns1.example.com", 3600),
        test_record("www", RecordType::A, "192.0.2.10", 600),
        test_record("www", RecordType::A, "192.0.2.11", 300),
    ];

    let diff = compute(ComputeArgs {
        zone: &zone,
        records: &records,
        keys: &keys,
        prev: &[],
        denial: DnssecDenial::Nsec,
        new_serial: 6,
        expiration: default_expiration(),
        expiration_jitter_secs: 0,
        force: false,
    });

    let www = OwnerName::parse_in_zone("www", &zone.name).unwrap();
    let rrsig = rrsigs_covering(&diff.added, &www, RECORD_TYPE_A);
    assert_eq!(rrsig.len(), 1);
    assert_eq!(rrsig[0].ttl, 300);
}

#[test]
fn withdrawal_publishes_the_delete_cds_pair() {
    let zone = test_zone();
    let keys = [test_key(
        &zone,
        1,
        DnssecKeyRole::Csk,
        DnssecKeyState::Active,
    )];
    let records = [test_record("@", RecordType::NS, "ns1.example.com", 3600)];

    let now = fixed_now();
    let diff = SignedViewParams {
        zone: &zone,
        new_serial: 2,
        records: &records,
        keys: &keys,
        prev: &[],
        denial: DnssecDenial::Nsec,
        now,
        inception: now - Duration::hours(1),
        expiration: default_expiration(),
        expiration_jitter_secs: 0,
        refresh_secs: 5 * 86_400,
        force: false,
        withdraw_parent_ds: true,
    }
    .compute()
    .unwrap();

    // RFC 8078, Section 4: a single 0-algorithm CDS/CDNSKEY pair replaces the
    // per-key set and asks the parent to delete the DS RRset.
    let cds = rows_of_type(&diff.added, DnssecRecordType::Cds);
    assert_eq!(cds.len(), 1);
    assert_eq!(cds[0].rdata.as_bytes(), &[0, 0, 0, 0, 0]);
    let cdnskey = rows_of_type(&diff.added, DnssecRecordType::Cdnskey);
    assert_eq!(cdnskey.len(), 1);
    assert_eq!(cdnskey[0].rdata.as_bytes(), &[0, 0, 3, 0, 0]);
}

#[test]
fn p384_keys_advertise_a_sha384_ds_digest() {
    use crate::dns::dnssec::{ds_rdata_for, to_wire_name};

    let zone = test_zone();
    let key = generate_key(
        &zone,
        DnssecAlgorithm::EcdsaP384Sha384,
        DnssecKeyRole::Csk,
        DnssecKeyState::Active,
        fixed_now(),
        fixed_now(),
    )
    .unwrap();

    let apex = to_wire_name(zone.name.to_wire()).unwrap();
    let rdata = ds_rdata_for(&key, &apex).unwrap();
    // RFC 6605, Section 4 pairs P-384 with a SHA-384 (type 4) DS digest.
    assert_eq!(rdata.as_bytes()[3], 4);
    assert_eq!(rdata.as_bytes().len(), 4 + 48);
}

#[test]
fn algorithm_rollover_double_signs_zone_data_while_published() {
    let zone = test_zone();
    let old = test_key(&zone, 1, DnssecKeyRole::Csk, DnssecKeyState::Active);
    let mut new = generate_key(
        &zone,
        DnssecAlgorithm::Ed25519,
        DnssecKeyRole::Csk,
        DnssecKeyState::Published,
        fixed_now(),
        fixed_now(),
    )
    .unwrap();
    new.id = 2;
    let keys = [old, new];
    let records = [test_record("@", RecordType::NS, "ns1.example.com", 3600)];

    let diff = compute(ComputeArgs {
        zone: &zone,
        records: &records,
        keys: &keys,
        prev: &[],
        denial: DnssecDenial::Nsec,
        new_serial: 2,
        expiration: default_expiration(),
        expiration_jitter_secs: 0,
        force: false,
    });

    // RFC 6840, Section 5.11: every algorithm in the DNSKEY RRset must sign
    // all data, so the pre-published new-algorithm key signs immediately.
    let apex = OwnerName::apex();
    assert_eq!(
        rrsigs_covering(&diff.added, &apex, RecordType::NS.wire_type() as i32).len(),
        2
    );
}

#[test]
fn algorithm_rollover_keeps_the_retired_old_algorithm_signing() {
    let zone = test_zone();
    let old = test_key(&zone, 1, DnssecKeyRole::Csk, DnssecKeyState::Retired);
    let mut new = generate_key(
        &zone,
        DnssecAlgorithm::Ed25519,
        DnssecKeyRole::Csk,
        DnssecKeyState::Active,
        fixed_now(),
        fixed_now(),
    )
    .unwrap();
    new.id = 2;
    let keys = [old, new];
    let records = [test_record("@", RecordType::NS, "ns1.example.com", 3600)];

    let diff = compute(ComputeArgs {
        zone: &zone,
        records: &records,
        keys: &keys,
        prev: &[],
        denial: DnssecDenial::Nsec,
        new_serial: 2,
        expiration: default_expiration(),
        expiration_jitter_secs: 0,
        force: false,
    });

    // The old DNSKEY is still served, so the old algorithm must keep covering
    // all data until the key is removed (RFC 6840, Section 5.11).
    let apex = OwnerName::apex();
    assert_eq!(
        rrsigs_covering(&diff.added, &apex, RecordType::NS.wire_type() as i32).len(),
        2
    );
}
