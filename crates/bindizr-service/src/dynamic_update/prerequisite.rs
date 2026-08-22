//! RFC 2136, Section 3.2: every prerequisite is checked against the zone
//! before any update is applied.

use bindizr_core::dns::name::OwnerName;
use bindizr_db::repository::LockLevel;

use super::{DynamicUpdateError, Prerequisite, owner_in_zone};
use crate::{
    RepositoryTx,
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    record::RecordService,
};

pub(super) async fn evaluate_prerequisites_tx(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    prerequisites: &[Prerequisite],
) -> Result<(), DynamicUpdateError> {
    if prerequisites.is_empty() {
        return Ok(());
    }

    let zone_records = RecordService::list_tx(tx, zone.id, LockLevel::Exclusive).await?;
    evaluate_against_records(zone, prerequisites, &zone_records)
}

fn evaluate_against_records(
    zone: &Zone,
    prerequisites: &[Prerequisite],
    zone_records: &[Record],
) -> Result<(), DynamicUpdateError> {
    for prerequisite in prerequisites {
        match prerequisite {
            Prerequisite::NameInUse { name } => {
                let owner = owner_in_zone(name, &zone.name)?;
                if !owner_exists(&owner, zone_records) {
                    return Err(DynamicUpdateError::NxDomain(format!(
                        "owner '{}' does not exist",
                        owner
                    )));
                }
            }
            Prerequisite::NameNotInUse { name } => {
                let owner = owner_in_zone(name, &zone.name)?;
                if owner_exists(&owner, zone_records) {
                    return Err(DynamicUpdateError::YxDomain(format!(
                        "owner '{}' exists",
                        owner
                    )));
                }
            }
            Prerequisite::RrsetInUse { name, record_type } => {
                let owner = owner_in_zone(name, &zone.name)?;
                if !rrset_exists(&owner, record_type, zone_records) {
                    return Err(DynamicUpdateError::NxRrset(format!(
                        "RRset {} {} does not exist",
                        owner, record_type
                    )));
                }
            }
            Prerequisite::RrsetNotInUse { name, record_type } => {
                let owner = owner_in_zone(name, &zone.name)?;
                if rrset_exists(&owner, record_type, zone_records) {
                    return Err(DynamicUpdateError::YxRrset(format!(
                        "RRset {} {} exists",
                        owner, record_type
                    )));
                }
            }
            Prerequisite::RrInUse {
                name,
                record_type,
                value,
                priority,
            } => {
                let owner = owner_in_zone(name, &zone.name)?;
                let exists = zone_records.iter().any(|record| {
                    record.name == owner
                        && record.record_type == *record_type
                        && record
                            .record_type
                            .values_equal(&record.value, None, value, None)
                        && record.priority == *priority
                });

                if !exists {
                    return Err(DynamicUpdateError::NxRrset(format!(
                        "RR {} {} not found",
                        owner, record_type
                    )));
                }
            }
        }
    }

    Ok(())
}

/// The apex always exists: the zone itself owns its SOA and NS records.
fn owner_exists(owner: &OwnerName, records: &[Record]) -> bool {
    owner.is_apex() || records.iter().any(|record| record.name == *owner)
}

fn rrset_exists(owner: &OwnerName, record_type: &RecordType, records: &[Record]) -> bool {
    records
        .iter()
        .any(|record| record.name == *owner && record.record_type == *record_type)
}
