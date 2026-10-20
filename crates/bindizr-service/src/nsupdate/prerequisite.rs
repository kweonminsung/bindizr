//! Prerequisites against the complete served zone (RFC 2136, Section 3.2).

use std::collections::{BTreeMap, BTreeSet};

use bindizr_core::dns::{message::Rtype, name::OwnerName, record::Rdata};
use bindizr_db::LockLevel;

use super::NsupdateError;
use crate::{
    Transaction,
    error::ServiceError,
    model::{dnssec_record::DnssecRecord, record::Record, zone::Zone},
};

/// An UPDATE prerequisite with a checked owner and wire type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Prerequisite {
    /// CLASS ANY, TYPE ANY: the owner must hold at least one record.
    NameExists { name: OwnerName },
    /// CLASS NONE, TYPE ANY: the owner must hold no records.
    NameAbsent { name: OwnerName },
    /// CLASS ANY: the record set must exist.
    RecordSetExists { name: OwnerName, record_type: Rtype },
    /// CLASS NONE: the record set must not exist.
    RecordSetAbsent { name: OwnerName, record_type: Rtype },
    /// CLASS IN: exact RRset match (RFC 2136, Section 3.2.3).
    RecordValueMatches {
        name: OwnerName,
        record_type: Rtype,
        rdata: Rdata,
    },
}

impl Prerequisite {
    /// The checked owner.
    pub(crate) fn name(&self) -> &OwnerName {
        match self {
            Self::NameExists { name }
            | Self::NameAbsent { name }
            | Self::RecordSetExists { name, .. }
            | Self::RecordSetAbsent { name, .. }
            | Self::RecordValueMatches { name, .. } => name,
        }
    }

    /// The wire type; `None` denotes a name-only prerequisite.
    pub(crate) fn record_type(&self) -> Option<Rtype> {
        match self {
            Self::NameExists { .. } | Self::NameAbsent { .. } => None,
            Self::RecordSetExists { record_type, .. }
            | Self::RecordSetAbsent { record_type, .. }
            | Self::RecordValueMatches { record_type, .. } => Some(*record_type),
        }
    }
}

/// Canonical RDATA sets, excluding TTL (RFC 2136, Sections 1.1 and 3.2.3).
pub(crate) type RecordSets = BTreeMap<(OwnerName, Rtype), BTreeSet<Rdata>>;

/// The complete served zone at this transaction's serial, under the caller's
/// zone lock: the SOA, ordinary and signer-generated records.
pub(crate) async fn served_record_sets_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
) -> Result<RecordSets, NsupdateError> {
    let records = bindizr_db::record::list_tx(tx, zone.id, LockLevel::Unlocked).await?;
    let derived = bindizr_db::dnssec_record::list_tx(tx, zone.id, LockLevel::Unlocked).await?;
    Ok(zone_record_sets(zone, &records, &derived)?)
}

/// Evaluate one prerequisite in wire order (RFC 2136, Section 3.2.5); a
/// value-dependent set joins `wanted` for the whole-set comparison.
pub(crate) fn evaluate_prerequisite(
    served: &RecordSets,
    prerequisite: &Prerequisite,
    wanted: &mut RecordSets,
) -> Result<(), NsupdateError> {
    let name = prerequisite.name();
    match prerequisite {
        Prerequisite::NameExists { .. } => {
            if !served.keys().any(|(owner, _)| owner == name) {
                return Err(NsupdateError::NxDomain(format!(
                    "owner '{name}' does not exist"
                )));
            }
        }
        Prerequisite::NameAbsent { .. } => {
            if served.keys().any(|(owner, _)| owner == name) {
                return Err(NsupdateError::YxDomain(format!("owner '{name}' exists")));
            }
        }
        Prerequisite::RecordSetExists { record_type, .. } => {
            if !served.contains_key(&(name.clone(), *record_type)) {
                return Err(NsupdateError::NxRrset(format!(
                    "no {record_type} records at {name}"
                )));
            }
        }
        Prerequisite::RecordSetAbsent { record_type, .. } => {
            if served.contains_key(&(name.clone(), *record_type)) {
                return Err(NsupdateError::YxRrset(format!(
                    "{record_type} records at {name} exist"
                )));
            }
        }
        Prerequisite::RecordValueMatches {
            record_type, rdata, ..
        } => {
            wanted
                .entry((name.clone(), *record_type))
                .or_default()
                .insert(rdata.clone());
        }
    }
    Ok(())
}

/// Compare every value-dependent prerequisite set whole with the served one
/// (RFC 2136, Section 3.2.3), once the section has been read.
pub(crate) fn evaluate_record_set_prerequisites(
    served: &RecordSets,
    wanted: &RecordSets,
) -> Result<(), NsupdateError> {
    for (key, values) in wanted {
        if served.get(key) != Some(values) {
            return Err(NsupdateError::NxRrset(format!(
                "{} records at {} are not the ones the prerequisite names",
                key.1, key.0,
            )));
        }
    }
    Ok(())
}

/// Combine SOA, ordinary and DNSSEC records for comparison.
/// Invalid stored RDATA is a server error.
fn zone_record_sets(
    zone: &Zone,
    records: &[Record],
    derived: &[DnssecRecord],
) -> Result<RecordSets, ServiceError> {
    let mut sets = RecordSets::new();
    let mut insert = |name: OwnerName, record_type: Rtype, rdata: Rdata| {
        let rdata = rdata.to_canonical(record_type).map_err(|e| {
            ServiceError::internal_with_source("failed to decode stored prerequisite content", e)
        })?;
        sets.entry((name, record_type)).or_default().insert(rdata);
        Ok::<(), ServiceError>(())
    };
    let soa = zone
        .soa_rdata(zone.serial)
        .map_err(|e| ServiceError::internal_with_source("failed to encode the zone's SOA", e))?;
    insert(OwnerName::apex(), Rtype::SOA, soa)?;
    for record in records {
        let rdata = record
            .to_rdata()
            .map_err(|e| ServiceError::internal_with_source("failed to encode a zone record", e))?;
        insert(
            record.name.clone(),
            Rtype::from_int(record.record_type.wire_type()),
            rdata,
        )?;
    }
    for record in derived {
        insert(
            record.name.clone(),
            Rtype::from_int(record.record_type.wire_type()),
            record.rdata.clone(),
        )?;
    }
    Ok(sets)
}
