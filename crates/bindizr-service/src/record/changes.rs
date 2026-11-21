//! Record row mutations and their matching IXFR journal entries in the caller's transaction.

use bindizr_core::dns::Serial;
use bindizr_core::model::record::{Record, RecordId};
use bindizr_core::model::zone_change::{ChangeOperation, JournalRecordType, ZoneChange};

use crate::Transaction;
use crate::error::ServiceError;

/// Insert records with their ADD zone changes for IXFR. The caller has
/// already validated the rows.
pub(crate) async fn create_with_changes_tx(
    tx: &mut Transaction<'_>,
    new_serial: Serial,
    records: &[Record],
) -> Result<Vec<Record>, ServiceError> {
    if records.is_empty() {
        return Ok(Vec::new());
    }

    let created_records = bindizr_db::record::create_many_tx(tx, records).await?;
    let changes: Vec<ZoneChange> = created_records
        .iter()
        .map(|record| ZoneChange {
            zone_id: record.zone_id,
            serial: new_serial,
            operation: ChangeOperation::Add,
            record_name: record.name.clone(),
            record_type: JournalRecordType::User(record.record_type),
            record_value: Some(record.value.clone()),
            record_rdata: None,
            record_ttl: record.ttl,
            record_priority: record.priority,
        })
        .collect();

    bindizr_db::zone_change::create_many_tx(tx, &changes).await?;

    Ok(created_records)
}

/// Update one record with its DEL(old)+ADD(new) zone changes for IXFR. The
/// caller has already validated the row.
pub(crate) async fn update_with_changes_tx(
    tx: &mut Transaction<'_>,
    new_serial: Serial,
    existing_record: &Record,
    updated_record: Record,
) -> Result<Record, ServiceError> {
    let updated_record = bindizr_db::record::update_tx(tx, updated_record).await?;

    let change = |operation, record: &Record| ZoneChange {
        zone_id: record.zone_id,
        serial: new_serial,
        operation,
        record_name: record.name.clone(),
        record_type: JournalRecordType::User(record.record_type),
        record_value: Some(record.value.clone()),
        record_rdata: None,
        record_ttl: record.ttl,
        record_priority: record.priority,
    };
    let changes = [
        change(ChangeOperation::Delete, existing_record),
        change(ChangeOperation::Add, &updated_record),
    ];

    bindizr_db::zone_change::create_many_tx(tx, &changes).await?;

    Ok(updated_record)
}

/// Delete records with their DEL zone changes for IXFR.
pub(crate) async fn delete_with_changes_tx(
    tx: &mut Transaction<'_>,
    new_serial: Serial,
    records: &[Record],
) -> Result<(), ServiceError> {
    if records.is_empty() {
        return Ok(());
    }

    let record_ids: Vec<RecordId> = records.iter().map(|record| record.id).collect();

    bindizr_db::record::delete_many_tx(tx, &record_ids).await?;

    let changes: Vec<ZoneChange> = records
        .iter()
        .map(|record| ZoneChange {
            zone_id: record.zone_id,
            serial: new_serial,
            operation: ChangeOperation::Delete,
            record_name: record.name.clone(),
            record_type: JournalRecordType::User(record.record_type),
            record_value: Some(record.value.clone()),
            record_rdata: None,
            record_ttl: record.ttl,
            record_priority: record.priority,
        })
        .collect();

    bindizr_db::zone_change::create_many_tx(tx, &changes).await?;

    Ok(())
}
