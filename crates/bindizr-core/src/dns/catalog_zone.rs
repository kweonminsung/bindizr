//! The catalog zone (RFC 9432) as a wire artifact: how a member is named in
//! the catalog Bindizr serves, and how the members are read back out of a
//! catalog another server serves.

use ring::digest::{SHA256, digest};
use thiserror::Error;

use crate::dns::{
    message::{Name, Rtype},
    name::{OwnerName, ParseNameError, ZoneName},
    query::TransferRecord,
};

/// A member zone's unique-id label (RFC 9432, Section 4.1): truncated
/// SHA-256, so every zone name fits one stable label with negligible collision risk.
pub(crate) fn zone_name_to_member_id(zone_name: &str) -> String {
    // Case-insensitive per RFC 4343, matching the catalog digest.
    let digest = digest(&SHA256, zone_name.to_ascii_lowercase().as_bytes());
    hex::encode(&digest.as_ref()[..16])
}

/// Why a transferred catalog zone could not be read as one.
#[derive(Debug, Error)]
pub enum ExtractMemberZonesError {
    #[error("the catalog carries no version record (RFC 9432, Section 4.2.1)")]
    MissingVersion,
    #[error("the catalog is schema version '{found}', not 2 (RFC 9432, Section 4.2.1)")]
    UnsupportedVersion { found: String },
    #[error("invalid owner name '{name}': {source}")]
    OwnerName {
        name: String,
        #[source]
        source: ParseNameError,
    },
    #[error("member record at '{name}' does not hold a name")]
    MemberRdata { name: String },
    #[error("member '{name}' is not a zone name: {source}")]
    MemberName {
        name: String,
        #[source]
        source: ParseNameError,
    },
}

/// The member zones a transferred catalog lists, sorted and without
/// repeats: the PTR targets directly under `zones.<catalog>` (RFC 9432,
/// Section 4.3), once the catalog's version record says schema 2
/// (Section 4.2.1). Every other record is the catalog's own metadata.
pub fn extract_member_zones(
    records: &[TransferRecord],
    catalog: &ZoneName,
) -> Result<Vec<ZoneName>, ExtractMemberZonesError> {
    let mut version = None;
    let mut members = Vec::new();
    for record in records {
        let owner = OwnerName::parse_absolute_in_zone(&record.name, catalog).map_err(|source| {
            ExtractMemberZonesError::OwnerName {
                name: record.name.clone(),
                source,
            }
        })?;
        let labels = owner.labels();
        match record.rtype {
            Rtype::TXT if labels == [b"version".to_vec()] => {
                version = Some(record.rdata.as_bytes().to_vec());
            }
            Rtype::PTR if labels.len() == 2 && labels[1] == b"zones" => {
                let target = Name::<Vec<u8>>::from_octets(record.rdata.as_bytes().to_vec())
                    .map_err(|_| ExtractMemberZonesError::MemberRdata {
                        name: record.name.clone(),
                    })?
                    .to_string();
                let member = ZoneName::parse(&target).map_err(|source| {
                    ExtractMemberZonesError::MemberName {
                        name: target,
                        source,
                    }
                })?;
                members.push(member);
            }
            _ => {}
        }
    }
    match version {
        None => return Err(ExtractMemberZonesError::MissingVersion),
        // One character-string, "2": the rdata is its length byte and the digit.
        Some(rdata) if rdata == [1, b'2'] => {}
        Some(rdata) => {
            let found = rdata
                .first()
                .map(|len| &rdata[1..rdata.len().min(1 + usize::from(*len))])
                .map(String::from_utf8_lossy)
                .unwrap_or_default()
                .into_owned();
            return Err(ExtractMemberZonesError::UnsupportedVersion { found });
        }
    }
    members.sort();
    members.dedup();
    Ok(members)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{name::encode_name, record::Rdata};

    /// A transfer record with the wire form of one presentation name as RDATA.
    fn name_record(owner: &str, rtype: Rtype, target: &str) -> TransferRecord {
        TransferRecord {
            name: owner.to_string(),
            rtype,
            ttl: 0,
            rdata: Rdata::new(encode_name(target).unwrap()).unwrap(),
        }
    }

    /// The catalog's version TXT record with the given character-string.
    fn version_record(catalog: &str, version: &[u8]) -> TransferRecord {
        let mut rdata = vec![version.len() as u8];
        rdata.extend_from_slice(version);
        TransferRecord {
            name: format!("version.{catalog}."),
            rtype: Rtype::TXT,
            ttl: 0,
            rdata: Rdata::new(rdata).unwrap(),
        }
    }

    /// Verify that `extract_member_zones` reads the PTR members under `zones`,
    /// sorted and without repeats, and passes the catalog's other records over.
    #[test]
    fn extract_member_zones_reads_ptr_members_under_zones_label() {
        let catalog = ZoneName::parse("catalog.example").unwrap();
        let records = [
            name_record("catalog.example.", Rtype::NS, "invalid."),
            version_record("catalog.example", b"2"),
            name_record("b1.zones.catalog.example.", Rtype::PTR, "Zone-B.example."),
            name_record("a1.zones.catalog.example.", Rtype::PTR, "zone-a.example."),
            name_record("a2.zones.catalog.example.", Rtype::PTR, "zone-a.example."),
            // A property of a member (Section 4.4), not a member.
            name_record(
                "group.a1.zones.catalog.example.",
                Rtype::PTR,
                "other.example.",
            ),
            name_record("stray.catalog.example.", Rtype::PTR, "stray.example."),
        ];

        let members = extract_member_zones(&records, &catalog).unwrap();

        assert_eq!(
            members,
            vec![
                ZoneName::parse("zone-a.example").unwrap(),
                ZoneName::parse("zone-b.example").unwrap(),
            ]
        );
    }

    /// Verify that `extract_member_zones` refuses a catalog without a version
    /// record, with another schema version, or with a record outside the zone.
    #[test]
    fn extract_member_zones_rejects_missing_or_foreign_version_and_foreign_owner() {
        let catalog = ZoneName::parse("catalog.example").unwrap();
        let member = name_record("a1.zones.catalog.example.", Rtype::PTR, "zone-a.example.");

        let missing = extract_member_zones(std::slice::from_ref(&member), &catalog).unwrap_err();
        assert!(matches!(missing, ExtractMemberZonesError::MissingVersion));

        let foreign_version = extract_member_zones(
            &[version_record("catalog.example", b"1"), member.clone()],
            &catalog,
        )
        .unwrap_err();
        assert!(
            matches!(&foreign_version, ExtractMemberZonesError::UnsupportedVersion { found } if found == "1"),
            "{foreign_version}"
        );

        let foreign_owner = extract_member_zones(
            &[
                version_record("catalog.example", b"2"),
                name_record("a1.zones.other.example.", Rtype::PTR, "zone-a.example."),
            ],
            &catalog,
        )
        .unwrap_err();
        assert!(
            matches!(foreign_owner, ExtractMemberZonesError::OwnerName { .. }),
            "{foreign_owner}"
        );
    }

    /// Verify that `zone_name_to_member_id` is stable and case insensitive.
    #[test]
    fn zone_name_to_member_id_preserves_identity_across_case_changes() {
        let id = zone_name_to_member_id("example.com");
        assert_eq!(id, zone_name_to_member_id("example.com"));
        assert_eq!(id, zone_name_to_member_id("EXAMPLE.COM"));
        assert!(
            id.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
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
        assert!(zone_name_to_member_id(&long).len() <= 63);
    }

    /// Verify that `zone_name_to_member_id` distinguishes dot from dash.
    #[test]
    fn zone_name_to_member_id_distinguishes_dot_from_dash() {
        // RFC 9432, Section 4.1 requires unique ids.
        assert_ne!(
            zone_name_to_member_id("a.b.example.com"),
            zone_name_to_member_id("a-b.example.com")
        );
    }
}
