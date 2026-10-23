//! Catalog member identities and schema-2 member extraction (RFC 9432).

use std::collections::{HashMap, HashSet};

use ring::digest::{SHA256, digest};
use thiserror::Error;

use crate::dns::{
    Serial, SoaInterval, Ttl,
    message::{Name, Rtype},
    name::{MAX_WIRE_NAME_LEN, OwnerName, ParseNameError, ZoneName},
    query::TransferRecord,
};

/// The virtual catalog's SOA metadata, without a managed-zone row or signing settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogZone {
    pub name: ZoneName,
    pub serial: Serial,
    pub default_ttl: Ttl,
    pub refresh: SoaInterval,
    pub retry: SoaInterval,
    pub expire: SoaInterval,
    pub minimum_ttl: Ttl,
}

/// Digest octets retained in stable catalog member IDs.
const MEMBER_ID_DIGEST_LEN: usize = 16;

/// Schema-2 subtree containing member PTR owners (RFC 9432, Section 4.1).
const MEMBER_SUBTREE: &str = "zones";

/// Wire space added before the catalog by one member ID and its subtree label.
const MEMBER_PREFIX_WIRE_LEN: usize = 1 + MEMBER_ID_DIGEST_LEN * 2 + 1 + MEMBER_SUBTREE.len();

/// Longest catalog name allowing every generated owner; the member prefix exceeds "version.".
pub(crate) const MAX_CATALOG_ZONE_WIRE_LEN: usize = MAX_WIRE_NAME_LEN - MEMBER_PREFIX_WIRE_LEN;

/// Build a schema-2 member PTR owner using the same prefix startup validates.
pub(crate) fn catalog_member_owner_name(catalog: &ZoneName, member_zone: &str) -> String {
    let member_id = zone_name_to_member_id(member_zone);
    format!("{member_id}.{MEMBER_SUBTREE}.{catalog}.")
}

/// Build a stable member label from truncated SHA-256 (RFC 9432, Section 4.1).
pub(crate) fn zone_name_to_member_id(zone_name: &str) -> String {
    // Case-insensitive per RFC 4343, matching the catalog digest.
    let digest = digest(&SHA256, zone_name.to_ascii_lowercase().as_bytes());
    hex::encode(&digest.as_ref()[..MEMBER_ID_DIGEST_LEN])
}

/// Why a transferred catalog zone could not be read as one.
#[derive(Debug, Error)]
pub enum ExtractMemberZonesError {
    #[error("the catalog carries no apex NS record (RFC 9432, Section 4)")]
    MissingApexNs,
    #[error("the catalog carries no version record (RFC 9432, Section 4.2.1)")]
    MissingVersion,
    #[error("the catalog carries more than one version record (RFC 9432, Section 4.2.1)")]
    VersionNotSingular,
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
    #[error("member node '{name}' holds more than one PTR record (RFC 9432, Section 4.1)")]
    MemberNodeNotSingular { name: String },
    #[error("zone '{name}' is listed under more than one member node (RFC 9432, Section 4.1)")]
    MemberRepeated { name: String },
}

/// Read sorted schema-2 members, ignoring duplicate records (RFC 5936, Section 2.2).
/// Reject conflicting versions, targets, or member nodes (RFC 9432, Sections 4.1–4.3).
pub fn extract_member_zones(
    records: &[TransferRecord],
    catalog: &ZoneName,
) -> Result<Vec<ZoneName>, ExtractMemberZonesError> {
    let mut version = None;
    let mut apex_ns = false;
    let mut member_nodes: HashMap<Vec<u8>, ZoneName> = HashMap::new();
    let mut listed: HashSet<&ZoneName> = HashSet::new();

    for record in records {
        let owner = OwnerName::parse_absolute_in_zone(&record.name, catalog).map_err(|source| {
            ExtractMemberZonesError::OwnerName {
                name: record.name.clone(),
                source,
            }
        })?;
        let labels = owner.labels();

        match record.rtype {
            Rtype::NS if owner.is_apex() => apex_ns = true,
            Rtype::TXT if labels == [b"version".to_vec()] => {
                if version
                    .as_deref()
                    .is_some_and(|value| value != record.rdata.as_bytes())
                {
                    return Err(ExtractMemberZonesError::VersionNotSingular);
                }

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

                match member_nodes.entry(labels[0].clone()) {
                    std::collections::hash_map::Entry::Occupied(entry)
                        if entry.get() != &member =>
                    {
                        return Err(ExtractMemberZonesError::MemberNodeNotSingular {
                            name: record.name.clone(),
                        });
                    }
                    std::collections::hash_map::Entry::Occupied(_) => {}
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(member);
                    }
                }
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

    // Different member IDs must not provision the same zone twice.
    let mut members: Vec<ZoneName> = member_nodes.into_values().collect();

    for member in &members {
        if !listed.insert(member) {
            return Err(ExtractMemberZonesError::MemberRepeated {
                name: member.to_string(),
            });
        }
    }

    // The AXFR client checks the SOA envelope; the catalog schema also needs
    // an apex NS (RFC 9432, Section 4), before any member is imported.
    if !apex_ns {
        return Err(ExtractMemberZonesError::MissingApexNs);
    }

    members.sort();

    Ok(members)
}

#[cfg(test)]
mod tests;
