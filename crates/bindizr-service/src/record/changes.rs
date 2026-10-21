//! Record row mutations and their matching IXFR journal entries in the caller's transaction.

use bindizr_core::{
    dns::Serial,
    model::{record::RecordId, zone::ZoneId},
};

use crate::{
    Transaction,
    error::ServiceError,
    model::{
        record::Record,
        zone_change::{ChangeOperation, JournalRecordType, ZoneChange},
    },
};

/// Insert records with their ADD zone changes for IXFR. The caller has
/// already validated the rows.
pub(crate) async fn create_with_changes_tx(
    tx: &mut Transaction<'_>,
    zone_id: ZoneId,
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
            zone_id,
            serial: new_serial,
            operation: ChangeOperation::Add,
            record_name: record.name.clone(),
            record_type: JournalRecordType::User(record.record_type),
            record_value: Some(record.value.clone()),
            record_rdata: None,
            record_ttl: record.ttl,
            record_priority: record.priority,
            derived: false,
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
    existing: &Record,
    updated: Record,
) -> Result<Record, ServiceError> {
    let updated = bindizr_db::record::update_tx(tx, updated).await?;
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
        derived: false,
    };
    let changes = [
        change(ChangeOperation::Delete, existing),
        change(ChangeOperation::Add, &updated),
    ];
    bindizr_db::zone_change::create_many_tx(tx, &changes).await?;
    Ok(updated)
}

/// Delete records with their DEL zone changes for IXFR.
pub(crate) async fn delete_with_changes_tx(
    tx: &mut Transaction<'_>,
    zone_id: ZoneId,
    new_serial: Serial,
    records: &[Record],
) -> Result<(), ServiceError> {
    if records.is_empty() {
        return Ok(());
    }

    let ids: Vec<RecordId> = records.iter().map(|r| r.id).collect();
    bindizr_db::record::delete_many_tx(tx, &ids).await?;
    let changes: Vec<ZoneChange> = records
        .iter()
        .map(|record| ZoneChange {
            zone_id,
            serial: new_serial,
            operation: ChangeOperation::Delete,
            record_name: record.name.clone(),
            record_type: JournalRecordType::User(record.record_type),
            record_value: Some(record.value.clone()),
            record_rdata: None,
            record_ttl: record.ttl,
            record_priority: record.priority,
            derived: false,
        })
        .collect();
    bindizr_db::zone_change::create_many_tx(tx, &changes).await?;
    Ok(())
}
