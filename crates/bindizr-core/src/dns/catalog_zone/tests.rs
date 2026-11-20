use std::slice;

use super::*;
use crate::dns::name;
use crate::dns::record::Rdata;

/// Verify that a catalog requires an apex NS, which unrelated NS records cannot supply.
#[test]
fn extract_member_zones_requires_apex_ns() {
    let catalog_zone_name = ZoneName::parse("catalog.example").unwrap();
    let version = version_record("catalog.example", b"2");

    for extra in [
        None,
        Some(name_record("child.catalog.example.", Rtype::NS, "invalid.")),
    ] {
        let mut records = vec![version.clone()];
        records.extend(extra);
        assert!(matches!(
            extract_member_zones(&records, &catalog_zone_name),
            Err(ExtractMemberZonesError::MissingApexNs)
        ));
    }

    for owner in [
        "catalog.example.",
        "CATALOG.EXAMPLE.",
        r"c\097talog.example.",
    ] {
        let ns = name_record(owner, Rtype::NS, "invalid.");
        let records = [
            version.clone(),
            ns.clone(),
            ns,
            name_record("catalog.example.", Rtype::NS, "ns.example."),
        ];

        assert!(
            extract_member_zones(&records, &catalog_zone_name)
                .unwrap()
                .is_empty()
        );
    }
}

/// Build a transfer record with the wire form of one presentation name as RDATA.
fn name_record(owner: &str, rtype: Rtype, target: &str) -> TransferRecord {
    TransferRecord {
        name: owner.to_string(),
        rtype,
        ttl: 0,
        rdata: Rdata::new(name::encode_name(target).unwrap()).unwrap(),
    }
}

/// Build the catalog's version TXT record with the given character-string.
fn version_record(catalog_zone_name: &str, version: &[u8]) -> TransferRecord {
    let mut rdata = vec![version.len() as u8];
    rdata.extend_from_slice(version);

    TransferRecord {
        name: format!("version.{catalog_zone_name}."),
        rtype: Rtype::TXT,
        ttl: 0,
        rdata: Rdata::new(rdata).unwrap(),
    }
}

/// Verify that `extract_member_zones` reads the PTR members under `zones`, sorted.
#[test]
fn extract_member_zones_reads_ptr_members_under_zones_label() {
    let catalog_zone_name = ZoneName::parse("catalog.example").unwrap();
    let records = [
        name_record("catalog.example.", Rtype::NS, "invalid."),
        version_record("catalog.example", b"2"),
        name_record("b1.zones.catalog.example.", Rtype::PTR, "Zone-B.example."),
        name_record("a1.zones.catalog.example.", Rtype::PTR, "zone-a.example."),
        // A property of a member (RFC 9432, Section 4.4), not a member.
        name_record(
            "group.a1.zones.catalog.example.",
            Rtype::PTR,
            "other.example.",
        ),
        name_record("stray.catalog.example.", Rtype::PTR, "stray.example."),
    ];

    let members = extract_member_zones(&records, &catalog_zone_name).unwrap();

    assert_eq!(
        members,
        vec![
            ZoneName::parse("zone-a.example").unwrap(),
            ZoneName::parse("zone-b.example").unwrap(),
        ]
    );
}

/// Verify that `extract_member_zones` refuses a node with two PTRs and a zone under two nodes.
#[test]
fn extract_member_zones_rejects_repeated_members() {
    let catalog_zone_name = ZoneName::parse("catalog.example").unwrap();
    let version = version_record("catalog.example", b"2");

    let two_ptrs = extract_member_zones(
        &[
            version.clone(),
            name_record("a1.zones.catalog.example.", Rtype::PTR, "zone-a.example."),
            name_record("a1.zones.catalog.example.", Rtype::PTR, "zone-b.example."),
        ],
        &catalog_zone_name,
    );

    assert!(
        matches!(
            two_ptrs,
            Err(ExtractMemberZonesError::MemberNodeNotSingular { .. })
        ),
        "{two_ptrs:?}"
    );

    let two_nodes = extract_member_zones(
        &[
            version,
            name_record("a1.zones.catalog.example.", Rtype::PTR, "zone-a.example."),
            name_record("a2.zones.catalog.example.", Rtype::PTR, "Zone-A.example."),
        ],
        &catalog_zone_name,
    );

    assert!(
        matches!(&two_nodes, Err(ExtractMemberZonesError::MemberRepeated { name }) if name == "zone-a.example"),
        "{two_nodes:?}"
    );
}

/// Verify that AXFR repetitions do not increase record set membership, regardless of TTL or name
/// case.
#[test]
fn extract_member_zones_ignores_repeated_transfer_records() {
    let catalog_zone_name = ZoneName::parse("catalog.example").unwrap();
    let mut repeated_version = version_record("CATALOG.example", b"2");
    repeated_version.ttl = 120;
    repeated_version.name = "VERSION.CATALOG.example.".to_string();
    let records = [
        name_record("catalog.example.", Rtype::NS, "invalid."),
        version_record("catalog.example", b"2"),
        name_record("a1.zones.catalog.example.", Rtype::PTR, "zone-a.example."),
        repeated_version,
        name_record(
            r"A\049.ZONES.CATALOG.example.",
            Rtype::PTR,
            "ZONE-A.example.",
        ),
    ];

    assert_eq!(
        extract_member_zones(&records, &catalog_zone_name).unwrap(),
        vec![ZoneName::parse("zone-a.example").unwrap()]
    );
}

/// Verify that missing, conflicting, or unsupported versions and foreign owners are rejected.
#[test]
fn extract_member_zones_rejects_missing_or_foreign_version_and_foreign_owner() {
    let catalog_zone_name = ZoneName::parse("catalog.example").unwrap();
    let member = name_record("a1.zones.catalog.example.", Rtype::PTR, "zone-a.example.");

    let missing = extract_member_zones(slice::from_ref(&member), &catalog_zone_name);

    assert!(matches!(
        missing,
        Err(ExtractMemberZonesError::MissingVersion)
    ));

    let two_versions = extract_member_zones(
        &[
            version_record("catalog.example", b"2"),
            version_record("catalog.example", b"3"),
            member.clone(),
        ],
        &catalog_zone_name,
    );

    assert!(
        matches!(
            two_versions,
            Err(ExtractMemberZonesError::VersionNotSingular)
        ),
        "{two_versions:?}"
    );

    let foreign_version = extract_member_zones(
        &[version_record("catalog.example", b"1"), member],
        &catalog_zone_name,
    );

    assert!(
        matches!(&foreign_version, Err(ExtractMemberZonesError::UnsupportedVersion { found }) if found == "1"),
        "{foreign_version:?}"
    );

    let foreign_owner = extract_member_zones(
        &[
            version_record("catalog.example", b"2"),
            name_record("a1.zones.other.example.", Rtype::PTR, "zone-a.example."),
        ],
        &catalog_zone_name,
    );

    assert!(
        matches!(
            foreign_owner,
            Err(ExtractMemberZonesError::OwnerName { .. })
        ),
        "{foreign_owner:?}"
    );
}

/// Verify that `zone_name_to_member_id` is stable and case insensitive.
#[test]
fn zone_name_to_member_id_preserves_identity_across_case_changes() {
    let id = zone_name_to_member_id(&ZoneName::parse("example.com").unwrap());

    assert_eq!(
        id,
        zone_name_to_member_id(&ZoneName::parse("example.com").unwrap())
    );
    assert_eq!(
        id,
        zone_name_to_member_id(&ZoneName::parse("EXAMPLE.COM").unwrap())
    );
    assert!(
        id.chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    );
}

/// Verify that `zone_name_to_member_id` fits a label for the longest zone name.
#[test]
fn zone_name_to_member_id_fits_label_limit_for_longest_zone_name() {
    // RFC 9432, Section 4.1: the id is one label, so the longest zone
    // name must still fit under the 63-byte label cap.
    let long = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");

    assert_eq!(long.len(), 253);
    assert!(zone_name_to_member_id(&ZoneName::parse(&long).unwrap()).len() <= 63);
}

/// Verify that `zone_name_to_member_id` distinguishes dot from dash.
#[test]
fn zone_name_to_member_id_distinguishes_dot_from_dash() {
    // RFC 9432, Section 4.1 requires unique ids.
    assert_ne!(
        zone_name_to_member_id(&ZoneName::parse("a.b.example.com").unwrap()),
        zone_name_to_member_id(&ZoneName::parse("a-b.example.com").unwrap())
    );
}
