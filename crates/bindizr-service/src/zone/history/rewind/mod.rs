//! Rewind a zone's user records to a serial by undoing its journal newest first.

use std::collections::HashMap;

use bindizr_core::{dns::Serial, model::zone::ZoneId};
use bindizr_db::LockLevel;

use crate::{
    Transaction, db,
    error::ServiceError,
    model::{
        record::{Record, RecordData, RecordKey},
        zone_change::{ChangeOperation, JournalRecordType, ZoneChange},
    },
};

/// Undo the zone's journal in `(target_serial, current_serial]` on the
/// current records, yielding the records at `target_serial`.
/// SOA rows are skipped (SOA state is restored from `zone_versions`).
pub(crate) async fn rewind_records_to_serial_tx(
    tx: &mut Transaction<'_>,
    zone_id: ZoneId,
    target_serial: Serial,
    current_serial: Serial,
) -> Result<Vec<RecordData>, ServiceError> {
    let records = db::record::list_tx(tx, zone_id, LockLevel::Unlocked).await?;
    let changes = db::zone_change::list_between_serials_tx(
        tx,
        zone_id,
        target_serial,
        current_serial,
        LockLevel::Unlocked,
    )
    .await?;

    Ok(undo_changes(records, &changes))
}

/// Undo `changes` — ordered by (serial, id) ascending — newest-first over
/// `records`, yielding the zone as it stood before them. A change the live
/// rows cannot explain is logged and passed over: a history that no longer
/// adds up must not block a rollback.
fn undo_changes(records: Vec<Record>, changes: &[ZoneChange]) -> Vec<RecordData> {
    let mut state: HashMap<RecordKey, Vec<RecordData>> = HashMap::new();
    for record in records {
        state
            .entry(record.match_key())
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
                "User change for '{}' {} carries no value; skipping during rewind",
                change.record_name,
                change.record_type
            );
            continue;
        };
        let record = RecordData {
            name: change.record_name.clone(),
            record_type: *record_type,
            value: record_value.to_string(),
            ttl: change.record_ttl,
            priority: change.record_priority,
        };
        let key = record.match_key();

        match change.operation {
            ChangeOperation::Add => match state.get_mut(&key).and_then(Vec::pop) {
                Some(_) => {}
                // Tolerated: history anomalies (e.g. rows removed outside
                // the change log) must not brick the rewind.
                None => log::warn!(
                    "No matching record to undo ADD of '{}' {} during rewind",
                    change.record_name,
                    change.record_type
                ),
            },
            ChangeOperation::Delete => {
                // The recorded row existed before this serial; restore it.
                state.entry(key).or_default().push(record);
            }
        }
    }

    let mut records: Vec<RecordData> = state.into_values().flatten().collect();
    sort_records(&mut records);
    records
}

/// The records at `serial`: the live records when it is the current serial,
/// otherwise rewound from the journal.
pub(crate) async fn list_records_at_serial_tx(
    tx: &mut Transaction<'_>,
    zone_id: ZoneId,
    serial: Serial,
    current_serial: Serial,
) -> Result<Vec<RecordData>, ServiceError> {
    if serial == current_serial {
        let mut records: Vec<RecordData> = db::record::list_tx(tx, zone_id, LockLevel::Unlocked)
            .await?
            .into_iter()
            .map(RecordData::from)
            .collect();
        sort_records(&mut records);
        Ok(records)
    } else {
        rewind_records_to_serial_tx(tx, zone_id, serial, current_serial).await
    }
}

/// Deterministic output order (hash-map iteration order is not).
fn sort_records(records: &mut [RecordData]) {
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
