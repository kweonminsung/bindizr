use super::*;

/// Build a zone fixture for the test.
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
        dnssec_policy_id: None,
        parent_ns_addrs: None,
        enabled: true,
        description: None,
        created_at: Utc::now(),
    }
}

/// Build a record fixture with the requested fields.
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

/// Verify that published key cosigns key record sets but not zone data.
#[test]
fn published_key_cosigns_key_record_sets_but_not_zone_data() {
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
    assert_eq!(
        records_of_type(&diff.added, DnssecRecordType::Dnskey).len(),
        2
    );
    assert_eq!(records_of_type(&diff.added, DnssecRecordType::Cds).len(), 2);
    // Both SEP keys sign the DNSKEY record set — a validator may arrive via either
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

/// Verify that retired key stays published but leaves the CDS set.
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
    // Still in the DNSKEY record set (cached signatures and a possibly lingering
    // old DS need it) and still co-signing that record set...
    assert_eq!(
        records_of_type(&diff.added, DnssecRecordType::Dnskey).len(),
        2
    );
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
    assert_eq!(records_of_type(&diff.added, DnssecRecordType::Cds).len(), 1);
    assert_eq!(
        records_of_type(&diff.added, DnssecRecordType::Cdnskey).len(),
        1
    );
    // And it signs no zone data.
    assert_eq!(rrsigs_covering(&diff.added, &apex, RECORD_TYPE_NS).len(), 1);
}

/// Verify that split keys partition key record sets from zone data.
#[test]
fn split_keys_partition_key_record_sets_from_zone_data() {
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
    assert_eq!(
        records_of_type(&diff.added, DnssecRecordType::Dnskey).len(),
        2
    );
    // Only the KSK is in the parent DS set and signs the key record sets
    // (RFC 7344, Section 4.1); only the ZSK signs zone data.
    assert_eq!(records_of_type(&diff.added, DnssecRecordType::Cds).len(), 1);
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

/// Verify that algorithm rollover double signs zone data while published.
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

    // RFC 6840, Section 5.11: every algorithm in the DNSKEY record set must sign
    // all data, so the pre-published new-algorithm key signs immediately.
    let apex = OwnerName::apex();
    assert_eq!(
        rrsigs_covering(&diff.added, &apex, RecordType::NS.wire_type() as i32).len(),
        2
    );
}

/// Verify that algorithm rollover keeps the retired old algorithm signing.
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
