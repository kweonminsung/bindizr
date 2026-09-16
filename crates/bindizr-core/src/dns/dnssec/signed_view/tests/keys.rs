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

/// Verify that p384 keys advertise a sha384 DS digest.
#[test]
fn p384_keys_advertise_a_sha384_ds_digest() {
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

    let apex = zone.name.to_wire_name().unwrap();
    let rdata = key.ds_rdata(&apex, key.algorithm.ds_digest_type()).unwrap();
    // RFC 6605, Section 4 pairs P-384 with a SHA-384 (type 4) DS digest.
    assert_eq!(rdata.as_bytes()[3], 4);
    assert_eq!(rdata.as_bytes().len(), 4 + 48);
}

/// Verify that `DnssecKey::ds_rdata` pairs the key with each supported digest.
#[test]
fn ds_rdata_pairs_the_key_with_each_supported_digest() {
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
    let apex = zone.name.to_wire_name().unwrap();

    let sha384 = key.ds_rdata(&apex, 4).unwrap();
    // A parent registering the SHA-256 form of the same key is as valid.
    let sha256 = key.ds_rdata(&apex, 2).unwrap();
    assert_eq!(&sha256.as_bytes()[..3], &sha384.as_bytes()[..3]);
    assert_eq!(sha256.as_bytes()[3], 2);
    assert_eq!(sha256.as_bytes().len(), 4 + 32);
    // A SHA-1 DS a parent still serves must match too (RFC 8624, Section 3.3).
    let sha1 = key.ds_rdata(&apex, 1).unwrap();
    assert_eq!(&sha1.as_bytes()[..3], &sha384.as_bytes()[..3]);
    assert_eq!(sha1.as_bytes()[3], 1);
    assert_eq!(sha1.as_bytes().len(), 4 + 20);
    assert!(key.ds_rdata(&apex, 3).is_err());
}

/// Verify that ed448 keys generate and sign.
#[test]
fn ed448_keys_generate_and_sign() {
    let zone = test_zone();
    let mut key = generate_key(
        &zone,
        DnssecAlgorithm::Ed448,
        DnssecKeyRole::Csk,
        DnssecKeyState::Active,
        fixed_now(),
        fixed_now(),
    )
    .unwrap();
    key.id = 1;
    let keys = [key];
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

    // Algorithm 16 only signs through the OpenSSL backend; this guards the
    // ring-to-OpenSSL fallback staying wired up.
    let apex = OwnerName::apex();
    let rrsigs = rrsigs_covering(&diff.added, &apex, RecordType::NS.wire_type() as i32);
    assert_eq!(rrsigs.len(), 1);
    assert_eq!(rrsigs[0].rdata.as_bytes()[2], 16);
}

/// Verify that rsa keys generate and sign.
#[test]
fn rsa_keys_generate_and_sign() {
    let zone = test_zone();
    let mut key = generate_key(
        &zone,
        DnssecAlgorithm::RsaSha256,
        DnssecKeyRole::Csk,
        DnssecKeyState::Active,
        fixed_now(),
        fixed_now(),
    )
    .unwrap();
    key.id = 1;
    let keys = [key];
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

    // RSA key generation also runs on the OpenSSL backend (ring only signs).
    let apex = OwnerName::apex();
    let rrsigs = rrsigs_covering(&diff.added, &apex, RecordType::NS.wire_type() as i32);
    assert_eq!(rrsigs.len(), 1);
    assert_eq!(rrsigs[0].rdata.as_bytes()[2], 8);
}
