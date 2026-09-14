use super::*;

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
    assert_eq!(
        records_of_type(&diff.added, DnssecRecordType::Dnskey).len(),
        1
    );
    // The CSK wants a parent DS, so it is advertised via CDS/CDNSKEY (RFC 7344).
    assert_eq!(records_of_type(&diff.added, DnssecRecordType::Cds).len(), 1);
    assert_eq!(
        records_of_type(&diff.added, DnssecRecordType::Cdnskey).len(),
        1
    );

    // One NSEC per authoritative name, chained apex → www → apex.
    let nsecs = records_of_type(&diff.added, DnssecRecordType::Nsec);
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
    let rrsigs = records_of_type(&diff.added, DnssecRecordType::Rrsig);
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

    assert!(records_of_type(&diff.added, DnssecRecordType::Nsec).is_empty());
    let params = records_of_type(&diff.added, DnssecRecordType::Nsec3param);
    assert_eq!(params.len(), 1);
    assert!(params[0].name.is_apex());
    // RFC 9276 parameters: SHA-1 (1), flags 0, iterations 0, empty salt.
    assert_eq!(params[0].rdata.as_bytes(), [1, 0, 0, 0, 0]);

    // One NSEC3 per authoritative name, at a hashed (base32) owner label.
    let nsec3s = records_of_type(&diff.added, DnssecRecordType::Nsec3);
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
    let cds = records_of_type(&diff.added, DnssecRecordType::Cds);
    assert_eq!(cds.len(), 1);
    assert_eq!(cds[0].rdata.as_bytes(), &[0, 0, 0, 0, 0]);
    let cdnskey = records_of_type(&diff.added, DnssecRecordType::Cdnskey);
    assert_eq!(cdnskey.len(), 1);
    assert_eq!(cdnskey[0].rdata.as_bytes(), &[0, 0, 3, 0, 0]);
}
