//! Rebuild a zone's user records by undoing its journal newest first.

use std::collections::HashMap;

use bindizr_core::dns::name::OwnerName;
use bindizr_db::repository::LockLevel;

use crate::{
    RepositoryTx,
    error::ServiceError,
    model::{
        record::{Record, RecordType},
        zone_change::{ChangeOperation, JournalRecordType, ZoneChange},
    },
    repository::RepositoryService,
};

/// A record as it existed at a past serial, rebuilt from the journal;
/// carries no database id.
#[derive(Debug, Clone)]
pub(crate) struct ReconstructedRecord {
    pub(crate) name: OwnerName,
    pub(crate) record_type: RecordType,
    pub(crate) value: String,
    pub(crate) ttl: i32,
    pub(crate) priority: Option<i32>,
}

impl From<Record> for ReconstructedRecord {
    /// Convert a current record into the historical reconstruction form.
    fn from(record: Record) -> Self {
        ReconstructedRecord {
            name: record.name,
            record_type: record.record_type,
            value: record.value,
            ttl: record.ttl,
            priority: record.priority,
        }
    }
}

impl ReconstructedRecord {
    /// The reconstruction identity of this record.
    pub(crate) fn match_key(&self) -> MatchKey {
        build_match_key(&self.name, &self.record_type, &self.value, self.priority)
    }
}

/// Hash key identifying a record for set matching: lowercased owner name,
/// type, and the canonical comparison form of the value(+priority).
pub(crate) type MatchKey = (String, String, String);

/// Build a canonical matching identity from a record's owner, type, and value.
pub(crate) fn build_match_key(
    name: &OwnerName,
    record_type: &RecordType,
    value: &str,
    priority: Option<i32>,
) -> MatchKey {
    (
        name.to_stored(),
        record_type.to_string(),
        record_type.canonical_value(value, priority).into_owned(),
    )
}

/// Build the reconstruction identity of a current record.
pub(crate) fn to_match_key(record: &Record) -> MatchKey {
    build_match_key(
        &record.name,
        &record.record_type,
        &record.value,
        record.priority,
    )
}

/// Reverse-apply the zone's journal in `(target_serial, current_serial]`
/// onto the current records, yielding the records at `target_serial`.
/// SOA rows are skipped (SOA state is restored from `zone_versions`).
pub(crate) async fn reconstruct_records_at_serial_tx(
    tx: &mut RepositoryTx<'_>,
    zone_id: i32,
    target_serial: i32,
    current_serial: i32,
) -> Result<Vec<ReconstructedRecord>, ServiceError> {
    let records = RepositoryService::list_records_tx(tx, zone_id, LockLevel::None).await?;
    let changes = RepositoryService::list_zone_changes_between_serials_tx(
        tx,
        zone_id,
        target_serial,
        current_serial,
        LockLevel::None,
    )
    .await?;

    Ok(undo_changes(records, &changes))
}

/// Undo `changes` — ordered by (serial, id) ascending — newest-first over
/// `records`, yielding the zone as it stood before them. A change the live
/// rows cannot explain is logged and passed over: a history that no longer
/// adds up must not block a rollback.
fn undo_changes(records: Vec<Record>, changes: &[ZoneChange]) -> Vec<ReconstructedRecord> {
    let mut state: HashMap<MatchKey, Vec<ReconstructedRecord>> = HashMap::new();
    for record in records {
        state
            .entry(to_match_key(&record))
            .or_default()
            .push(record.into());
    }

    for change in changes.iter().rev() {
        // Derived DNSSEC rows are not user data (rollback re-signs the
        // restored plane), and SOA markers are zone metadata the version row
        // already carries.
        let JournalRecordType::User(record_type) = &change.record_type else {
            continue;
        };
        let Some(record_value) = change.record_value.as_deref() else {
            log::warn!(
                "User change for '{}' {} carries no value; skipping during reconstruction",
                change.record_name,
                change.record_type
            );
            continue;
        };
        let record_type = record_type.clone();
        let key = build_match_key(
            &change.record_name,
            &record_type,
            record_value,
            change.record_priority,
        );

        match change.operation {
            ChangeOperation::Add => match state.get_mut(&key).and_then(Vec::pop) {
                Some(_) => {}
                // Tolerated: history anomalies (e.g. rows removed outside
                // the change log) must not brick reconstruction.
                None => log::warn!(
                    "No matching record to undo ADD of '{}' {} during reconstruction",
                    change.record_name,
                    change.record_type
                ),
            },
            ChangeOperation::Del => {
                // The recorded row existed before this serial; restore it.
                state.entry(key).or_default().push(ReconstructedRecord {
                    name: change.record_name.clone(),
                    record_type,
                    value: record_value.to_string(),
                    ttl: change.record_ttl,
                    priority: change.record_priority,
                });
            }
        }
    }

    let mut records: Vec<ReconstructedRecord> = state.into_values().flatten().collect();
    sort_records(&mut records);
    records
}

/// The records at `serial`: the live records when it is the current serial,
/// otherwise reconstructed from the journal.
pub(crate) async fn list_records_at_serial_tx(
    tx: &mut RepositoryTx<'_>,
    zone_id: i32,
    serial: i32,
    current_serial: i32,
) -> Result<Vec<ReconstructedRecord>, ServiceError> {
    if serial == current_serial {
        let mut records: Vec<ReconstructedRecord> =
            RepositoryService::list_records_tx(tx, zone_id, LockLevel::None)
                .await?
                .into_iter()
                .map(ReconstructedRecord::from)
                .collect();
        sort_records(&mut records);
        Ok(records)
    } else {
        reconstruct_records_at_serial_tx(tx, zone_id, serial, current_serial).await
    }
}

/// Deterministic output order (hash-map iteration order is not).
fn sort_records(records: &mut [ReconstructedRecord]) {
    records.sort_by(|a, b| {
        (&a.name, a.record_type.as_str(), &a.value).cmp(&(
            &b.name,
            b.record_type.as_str(),
            &b.value,
        ))
    });
}

#[cfg(test)]
mod tests;
