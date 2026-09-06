//! RFC 2136, Section 3.2: every prerequisite is checked against the zone
//! before any update is applied.

use bindizr_core::dns::name::OwnerName;
use bindizr_db::repository::LockLevel;

use super::{DynamicUpdateError, Prerequisite, parse_owner_in_zone};
use crate::{
    RepositoryTx,
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    repository::RepositoryService,
};

pub(crate) async fn evaluate_prerequisites_tx(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    prerequisites: &[Prerequisite],
) -> Result<(), DynamicUpdateError> {
    if prerequisites.is_empty() {
        return Ok(());
    }

    let zone_records =
        RepositoryService::list_records_tx(tx, zone.id, LockLevel::Exclusive).await?;

    for prerequisite in prerequisites {
        match prerequisite {
            Prerequisite::NameInUse { name } => {
                let owner = parse_owner_in_zone(name, &zone.name)?;
                if !has_owner(&owner, &zone_records) {
                    return Err(DynamicUpdateError::NxDomain(format!(
                        "owner '{}' does not exist",
                        owner
                    )));
                }
            }
            Prerequisite::NameNotInUse { name } => {
                let owner = parse_owner_in_zone(name, &zone.name)?;
                if has_owner(&owner, &zone_records) {
                    return Err(DynamicUpdateError::YxDomain(format!(
                        "owner '{}' exists",
                        owner
                    )));
                }
            }
            Prerequisite::RrsetInUse { name, record_type } => {
                let owner = parse_owner_in_zone(name, &zone.name)?;
                if !has_rrset(&owner, record_type, &zone_records) {
                    return Err(DynamicUpdateError::NxRrset(format!(
                        "no {} records at {}",
                        record_type, owner
                    )));
                }
            }
            Prerequisite::RrsetNotInUse { name, record_type } => {
                let owner = parse_owner_in_zone(name, &zone.name)?;
                if has_rrset(&owner, record_type, &zone_records) {
                    return Err(DynamicUpdateError::YxRrset(format!(
                        "{} records at {} exist",
                        record_type, owner
                    )));
                }
            }
            Prerequisite::RrInUse {
                name,
                record_type,
                value,
                priority,
            } => {
                let owner = parse_owner_in_zone(name, &zone.name)?;
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
                        "record {} {} not found",
                        owner, record_type
                    )));
                }
            }
        }
    }

    Ok(())
}

/// The apex always exists: the zone itself owns its SOA and NS records.
fn has_owner(owner: &OwnerName, records: &[Record]) -> bool {
    owner.is_apex() || records.iter().any(|record| record.name == *owner)
}

fn has_rrset(owner: &OwnerName, record_type: &RecordType, records: &[Record]) -> bool {
    records
        .iter()
        .any(|record| record.name == *owner && record.record_type == *record_type)
}
