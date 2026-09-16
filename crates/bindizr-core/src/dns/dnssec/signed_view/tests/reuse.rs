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

/// Verify that expirations spread across the jitter window.
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

    let expirations: BTreeSet<DateTime<Utc>> =
        records_of_type(&diff.added, DnssecRecordType::Rrsig)
            .iter()
            .filter_map(|row| row.expires_at)
            .collect();
    assert!(
        expirations.len() > 1,
        "one pass would come due for every signature at once: {expirations:?}"
    );
    let earliest = *expirations.iter().next().expect("signatures were emitted");
    let latest = *expirations
        .iter()
        .next_back()
        .expect("signatures were emitted");
    assert!(latest <= default_expiration());
    assert!(earliest > default_expiration() - Duration::seconds(window));
}

/// Verify that recompute against stored plane is empty.
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
    let stored = to_stored(&initial.added);

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

/// Verify that record change reuses unaffected signatures.
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
    let stored = to_stored(&initial.added);

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

/// Verify that signature inside refresh window is resigned.
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
    let stored = to_stored(&initial.added);
    let stored_rrsigs = records_of_type(&stored, DnssecRecordType::Rrsig).len();

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
        records_of_type(&diff.removed, DnssecRecordType::Rrsig).len(),
        stored_rrsigs
    );
    assert_eq!(
        records_of_type(&diff.added, DnssecRecordType::Rrsig).len(),
        stored_rrsigs
    );
    assert!(records_of_type(&diff.added, DnssecRecordType::Nsec).is_empty());
    assert!(records_of_type(&diff.removed, DnssecRecordType::Dnskey).is_empty());
}

/// Verify that force resigns every RRSET.
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
    let stored = to_stored(&initial.added);
    let stored_rrsigs = records_of_type(&stored, DnssecRecordType::Rrsig).len();

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
        records_of_type(&diff.added, DnssecRecordType::Rrsig).len(),
        stored_rrsigs
    );
    assert_eq!(
        records_of_type(&diff.removed, DnssecRecordType::Rrsig).len(),
        stored_rrsigs
    );
}
