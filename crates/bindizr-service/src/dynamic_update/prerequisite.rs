//! RFC 2136, Section 3.2: every prerequisite is checked against the zone
//! before any update is applied. Zone-class RRs are grouped by name and type
//! and must equal the zone's RRset there (Section 3.2.3).

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

/// Evaluate UPDATE prerequisites against the locked zone contents.
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

    let mut record_sets: Vec<WantedRecordSet<'_>> = Vec::new();
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
                if !has_record_set(&owner, record_type, &zone_records) {
                    return Err(DynamicUpdateError::NxRrset(format!(
                        "no {} records at {}",
                        record_type, owner
                    )));
                }
            }
            Prerequisite::RrsetNotInUse { name, record_type } => {
                let owner = parse_owner_in_zone(name, &zone.name)?;
                if has_record_set(&owner, record_type, &zone_records) {
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
                match record_sets.iter_mut().find(|record_set| {
                    record_set.owner == owner && record_set.record_type == *record_type
                }) {
                    Some(record_set) => record_set.records.push((value.as_str(), *priority)),
                    None => record_sets.push(WantedRecordSet {
                        owner,
                        record_type: record_type.clone(),
                        records: vec![(value.as_str(), *priority)],
                    }),
                }
            }
        }
    }

    for wanted in record_sets {
        let stored: Vec<&Record> = zone_records
            .iter()
            .filter(|record| {
                record.name == wanted.owner && record.record_type == wanted.record_type
            })
            .collect();
        if !is_same_record_set(&stored, &wanted.records) {
            return Err(DynamicUpdateError::NxRrset(format!(
                "{} records at {} are not the ones the prerequisite names",
                wanted.record_type, wanted.owner
            )));
        }
    }

    Ok(())
}

/// The RRs a prerequisite names at one owner and type, as value and priority.
struct WantedRecordSet<'a> {
    owner: OwnerName,
    record_type: RecordType,
    records: Vec<(&'a str, Option<i32>)>,
}

/// Whether the stored records of one name and type are exactly the RRs a
/// prerequisite names; compared both ways, so order and repeats do not matter.
fn is_same_record_set(stored: &[&Record], wanted: &[(&str, Option<i32>)]) -> bool {
    let matches = |record: &Record, (value, priority): &(&str, Option<i32>)| {
        record.has_rdata(value, *priority)
    };
    wanted
        .iter()
        .all(|expected| stored.iter().any(|record| matches(record, expected)))
        && stored
            .iter()
            .all(|record| wanted.iter().any(|expected| matches(record, expected)))
}

/// Check whether an owner exists, counting the apex as present because the zone owns its SOA
/// and NS records.
fn has_owner(owner: &OwnerName, records: &[Record]) -> bool {
    owner.is_apex() || records.iter().any(|record| record.name == *owner)
}

/// Check whether the zone contains records with the requested owner and type.
fn has_record_set(owner: &OwnerName, record_type: &RecordType, records: &[Record]) -> bool {
    records
        .iter()
        .any(|record| record.name == *owner && record.record_type == *record_type)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    /// Build a stored A record fixture with the given value.
    fn a_record(value: &str) -> Record {
        Record {
            id: 0,
            name: OwnerName::from_row("check"),
            record_type: RecordType::A,
            value: value.to_string(),
            ttl: 300,
            priority: None,
            zone_id: 1,
            created_at: Utc::now(),
        }
    }

    /// Verify that a prerequisite must name the whole RRset.
    #[test]
    fn a_prerequisite_must_name_the_whole_record_set() {
        let stored = [a_record("192.0.2.1"), a_record("192.0.2.2")];
        let stored: Vec<&Record> = stored.iter().collect();

        // RFC 2136, Section 3.2.3: a subset or a superset is not the RRset.
        assert!(!is_same_record_set(&stored, &[("192.0.2.1", None)]));
        assert!(!is_same_record_set(
            &stored,
            &[
                ("192.0.2.1", None),
                ("192.0.2.2", None),
                ("192.0.2.3", None)
            ]
        ));
        // Order and repeats in the request carry no meaning.
        assert!(is_same_record_set(
            &stored,
            &[
                ("192.0.2.2", None),
                ("192.0.2.1", None),
                ("192.0.2.2", None)
            ]
        ));
        assert!(!is_same_record_set(&[], &[("192.0.2.1", None)]));
    }
}
