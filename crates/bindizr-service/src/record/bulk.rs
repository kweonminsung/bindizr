use chrono::Utc;

use super::{RecordService, validation::validate_record_add_constraints};
use crate::{
    RepositoryTx,
    error::ServiceError,
    log_error, log_info, log_warn,
    model::{
        record::{Record, RecordType, RecordWithZone},
        zone::Zone,
        zone_change::ZoneChange,
    },
    repository::RepositoryService,
    serial::generate_serial,
    types::{BulkRecordItem, RecordValueRequest},
    zone::{snapshot::save_zone_snapshot_tx, validation::normalize_zone_name},
};

/// A record whose type and value are parsed and ready to insert. The owner name
/// is kept raw so the constraint validator can normalize it against the zone.
pub(super) struct PreparedRecord {
    pub owner_name: String,
    pub record_type: RecordType,
    pub value: String,
    pub ttl: Option<i32>,
    pub priority: Option<i32>,
}

/// Parse the record type and encode the value into storage form.
pub(super) fn prepare_record(
    name: &str,
    record_type: &str,
    value: &RecordValueRequest,
    ttl: Option<i32>,
    priority: Option<i32>,
) -> Result<PreparedRecord, ServiceError> {
    let record_type = record_type
        .parse::<RecordType>()
        .map_err(|_| ServiceError::BadRequest(format!("Invalid record type: {}", record_type)))?;
    let value = value
        .to_storage_value(&record_type)
        .map_err(ServiceError::BadRequest)?;

    Ok(PreparedRecord {
        owner_name: name.to_string(),
        record_type,
        value,
        ttl,
        priority,
    })
}

/// Validate and insert one record, appending it to `zone_records` and recording
/// an ADD zone change for IXFR. Shared by bulk insert and zone-file import.
pub(super) async fn insert_prepared_tx(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    zone_records: &mut Vec<Record>,
    new_serial: i32,
    prepared: &PreparedRecord,
) -> Result<Record, ServiceError> {
    let normalized_owner = validate_record_add_constraints(
        zone,
        zone_records,
        &prepared.owner_name,
        &prepared.record_type,
        &prepared.value,
        prepared.priority,
        None,
    )?;

    let created_record = RepositoryService::create_record_tx(
        tx,
        Record {
            id: 0, // Will be set by the database
            name: normalized_owner.stored_name,
            record_type: prepared.record_type.clone(),
            value: prepared.value.clone(),
            ttl: prepared.ttl,
            priority: prepared.priority,
            zone_id: zone.id,
            created_at: Utc::now(), // Will be set by the database
        },
    )
    .await
    .map_err(|e| {
        log_error!("Failed to create record: {}", e);
        ServiceError::Internal("Failed to create record".to_string())
    })?;

    zone_records.push(created_record.clone());

    RepositoryService::create_zone_change_tx(
        tx,
        ZoneChange {
            id: 0,
            zone_id: zone.id,
            serial: new_serial,
            operation: "ADD".to_string(),
            record_name: created_record.name.clone(),
            record_type: created_record.record_type.to_string(),
            record_value: created_record.value.clone(),
            record_ttl: created_record.ttl,
            record_priority: created_record.priority,
        },
    )
    .await
    .map_err(|e| {
        log_error!("Failed to create zone change: {}", e);
        ServiceError::Internal("Failed to create zone change".to_string())
    })?;

    Ok(created_record)
}

/// Delete one record, dropping it from `zone_records` and recording a DEL zone
/// change for IXFR. Used by zone-file import (`upsert`/`replace`).
pub(super) async fn delete_existing_record_tx(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    zone_records: &mut Vec<Record>,
    new_serial: i32,
    record: &Record,
) -> Result<(), ServiceError> {
    RepositoryService::delete_record_tx(tx, record.id)
        .await
        .map_err(|e| {
            log_error!("Failed to delete record: {}", e);
            ServiceError::Internal("Failed to delete record".to_string())
        })?;

    zone_records.retain(|r| r.id != record.id);

    RepositoryService::create_zone_change_tx(
        tx,
        ZoneChange {
            id: 0,
            zone_id: zone.id,
            serial: new_serial,
            operation: "DEL".to_string(),
            record_name: record.name.clone(),
            record_type: record.record_type.to_string(),
            record_value: record.value.clone(),
            record_ttl: record.ttl,
            record_priority: record.priority,
        },
    )
    .await
    .map_err(|e| {
        log_error!("Failed to create zone change: {}", e);
        ServiceError::Internal("Failed to create zone change".to_string())
    })?;

    Ok(())
}

/// Load the target zone inside the transaction, returning `NotFound` if missing.
pub(super) async fn load_zone_tx(
    tx: &mut RepositoryTx<'_>,
    zone_name: &str,
) -> Result<Zone, ServiceError> {
    let lookup_zone_name = normalize_zone_name(zone_name)?;
    match RepositoryService::get_zone_by_name_tx(tx, &lookup_zone_name).await {
        Ok(Some(zone)) => Ok(zone),
        Ok(None) => Err(ServiceError::NotFound(format!(
            "Zone with name '{}' not found",
            zone_name
        ))),
        Err(e) => {
            log_error!("Failed to fetch zone: {}", e);
            Err(ServiceError::Internal("Failed to fetch zone".to_string()))
        }
    }
}

impl RecordService {
    /// Insert many records into a zone in one transaction. The zone serial is
    /// incremented once, a single snapshot is saved, and a single NOTIFY is sent
    /// after commit. Either every record is inserted or none is.
    pub async fn create_bulk(
        zone_name: &str,
        items: &[BulkRecordItem],
    ) -> Result<Vec<RecordWithZone>, ServiceError> {
        if items.is_empty() {
            return Err(ServiceError::BadRequest(
                "no records provided for bulk insert".to_string(),
            ));
        }

        // Validate types and values up front so a malformed item fails fast.
        let prepared = items
            .iter()
            .map(|item| {
                prepare_record(
                    &item.name,
                    &item.record_type,
                    &item.value,
                    item.ttl,
                    item.priority,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut tx = RepositoryService::begin_tx("Failed to create records").await?;

        let apply_result = async {
            let zone = load_zone_tx(&mut tx, zone_name).await?;

            let mut zone_records =
                match RepositoryService::get_records_by_zone_id_tx(&mut tx, zone.id).await {
                    Ok(records) => records,
                    Err(e) => {
                        log_error!("Failed to load zone records: {}", e);
                        return Err(ServiceError::Internal(
                            "Failed to create records".to_string(),
                        ));
                    }
                };

            let new_serial = generate_serial(Some(zone.serial));

            // Validate each record (including intra-batch conflicts) up front,
            // then insert all rows and changes in one multi-row statement each.
            // New records are appended to `zone_records` so each iteration's
            // constraint check sees the ones before it, then split back off —
            // avoiding a clone of every record.
            let existing_count = zone_records.len();
            zone_records.reserve(prepared.len());
            for prepared_record in &prepared {
                let normalized_owner = validate_record_add_constraints(
                    &zone,
                    &zone_records,
                    &prepared_record.owner_name,
                    &prepared_record.record_type,
                    &prepared_record.value,
                    prepared_record.priority,
                    None,
                )?;

                zone_records.push(Record {
                    id: 0, // Will be set by the database
                    name: normalized_owner.stored_name,
                    record_type: prepared_record.record_type.clone(),
                    value: prepared_record.value.clone(),
                    ttl: prepared_record.ttl,
                    priority: prepared_record.priority,
                    zone_id: zone.id,
                    created_at: Utc::now(), // Will be set by the database
                });
            }
            let to_insert = zone_records.split_off(existing_count);

            let created_records = RepositoryService::create_records_tx(&mut tx, &to_insert).await?;

            let changes: Vec<ZoneChange> = created_records
                .iter()
                .map(|record| ZoneChange {
                    id: 0,
                    zone_id: zone.id,
                    serial: new_serial,
                    operation: "ADD".to_string(),
                    record_name: record.name.clone(),
                    record_type: record.record_type.to_string(),
                    record_value: record.value.clone(),
                    record_ttl: record.ttl,
                    record_priority: record.priority,
                })
                .collect();
            RepositoryService::create_zone_changes_tx(&mut tx, &changes).await?;

            // Increment zone serial once so IXFR consumers detect the batch
            RepositoryService::update_zone_serial_tx(&mut tx, zone.id, new_serial)
                .await
                .map_err(|e| {
                    log_error!("Failed to update zone serial: {}", e);
                    ServiceError::Internal("Failed to update zone serial".to_string())
                })?;

            save_zone_snapshot_tx(&mut tx, &zone, new_serial).await?;

            // `zone` is dead after this point, so hand its name over rather than
            // cloning it.
            Ok::<(Vec<Record>, String), ServiceError>((created_records, zone.name))
        }
        .await;

        let (created_records, zone_name) =
            RepositoryService::finish_tx(tx, apply_result, "Failed to create records").await?;

        log_info!(
            "event=record_bulk_create zone={} count={}",
            zone_name,
            created_records.len()
        );

        // Send NOTIFY to secondary servers
        if let Err(e) = crate::notify::send_notify_after_update(Some(&zone_name)).await {
            log_warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
        }

        Ok(created_records
            .into_iter()
            .map(|record| RecordWithZone::new(record, zone_name.clone()))
            .collect())
    }
}
