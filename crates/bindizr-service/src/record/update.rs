use super::{
    RecordService,
    validation::{normalize_record_owner_name, validate_record_update_constraints_normalized},
};
use crate::{
    error::{ErrorCode, ServiceError},
    log_error, log_info, log_warn,
    model::{
        record::{Record, RecordType, RecordWithZone},
        zone_change::ZoneChange,
    },
    repository::RepositoryService,
    serial::generate_serial,
    types::{UpdateRecordPatch, UpdateRecordRequest},
    zone::snapshot::save_zone_snapshot_tx,
};

/// The record's fields after a full request or a patch has been resolved
/// against the currently stored record. `storage_value` is already encoded.
struct ResolvedRecordUpdate {
    owner_name: String,
    record_type: RecordType,
    storage_value: String,
    ttl: Option<i32>,
    priority: Option<i32>,
}

impl RecordService {
    /// Full replacement (HTTP PUT): every field comes from the request.
    pub async fn update_by_id(
        record_id: i32,
        request: &UpdateRecordRequest,
    ) -> Result<RecordWithZone, ServiceError> {
        Self::update_locked(record_id, |_existing| {
            let record_type = parse_record_type(&request.record_type)?;
            let storage_value = request
                .value
                .to_storage_value(&record_type)
                .map_err(ServiceError::invalid_record_value)?;
            Ok(ResolvedRecordUpdate {
                owner_name: request.name.clone(),
                record_type,
                storage_value,
                ttl: request.ttl,
                priority: request.priority,
            })
        })
        .await
    }

    /// Partial update (CLI): omitted fields keep the stored record's value. The
    /// merge runs inside the transaction, against the row loaded there.
    pub async fn patch_by_id(
        record_id: i32,
        patch: &UpdateRecordPatch,
    ) -> Result<RecordWithZone, ServiceError> {
        Self::update_locked(record_id, |existing| {
            let record_type = match &patch.record_type {
                Some(record_type) => parse_record_type(record_type)?,
                None => existing.record_type.clone(),
            };
            let storage_value = match &patch.value {
                Some(value) => value
                    .to_storage_value(&record_type)
                    .map_err(ServiceError::invalid_record_value)?,
                None => existing.value.clone(),
            };
            // Only MX/SRV carry a priority, so retyping to any other type clears it.
            let priority = if matches!(record_type, RecordType::MX | RecordType::SRV) {
                patch.priority.or(existing.priority)
            } else {
                None
            };
            Ok(ResolvedRecordUpdate {
                owner_name: patch.name.clone().unwrap_or_else(|| existing.name.clone()),
                record_type,
                storage_value,
                ttl: patch.ttl.or(existing.ttl),
                priority,
            })
        })
        .await
    }

    /// Load the record inside the transaction, resolve the update against it,
    /// then write it, bumping the zone serial and recording DEL+ADD IXFR changes.
    async fn update_locked(
        record_id: i32,
        resolve: impl FnOnce(&Record) -> Result<ResolvedRecordUpdate, ServiceError>,
    ) -> Result<RecordWithZone, ServiceError> {
        // Resolve zone_id with a non-locking read so the tx locks zone before
        // record (the create/bulk/import order); the reverse can deadlock.
        let zone_id = match RepositoryService::get_record_by_id(record_id).await {
            Ok(Some(record)) => record.zone_id,
            Ok(None) => return Err(ServiceError::record_not_found(record_id)),
            Err(e) => {
                log_error!("Failed to fetch record: {}", e);
                return Err(ServiceError::internal("Failed to fetch record".to_string()));
            }
        };

        let mut tx = RepositoryService::begin_tx("Failed to update record").await?;

        let apply_result = async {
            let zone = match RepositoryService::get_zone_by_id_tx(&mut tx, zone_id).await {
                Ok(Some(zone)) => zone,
                Ok(None) => {
                    return Err(ServiceError::new(
                        ErrorCode::ZoneNotFound,
                        format!("Zone with id '{}' not found", zone_id),
                    ));
                }
                Err(e) => {
                    log_error!("Failed to fetch zone: {}", e);
                    return Err(ServiceError::internal("Failed to fetch zone".to_string()));
                }
            };

            let existing_record =
                match RepositoryService::get_record_by_id_tx(&mut tx, record_id).await {
                    Ok(Some(record)) if record.zone_id == zone.id => record,
                    Ok(Some(_)) | Ok(None) => {
                        return Err(ServiceError::record_not_found(record_id));
                    }
                    Err(e) => {
                        log_error!("Failed to fetch record: {}", e);
                        return Err(ServiceError::internal("Failed to fetch record".to_string()));
                    }
                };

            let resolved = resolve(&existing_record)?;

            // Only records sharing the new owner name can conflict, so load just
            // those instead of the whole zone.
            let lookup_owner = normalize_record_owner_name(&resolved.owner_name, &zone.name)?;
            let zone_records = match RepositoryService::get_records_by_zone_id_and_name_tx(
                &mut tx,
                zone.id,
                &lookup_owner.stored_name,
            )
            .await
            {
                Ok(records) => records,
                Err(e) => {
                    log_error!("Failed to load zone records: {}", e);
                    return Err(ServiceError::internal(
                        "Failed to update record".to_string(),
                    ));
                }
            };

            let mut candidate_updated = Record {
                id: existing_record.id,
                name: resolved.owner_name.clone(),
                record_type: resolved.record_type.clone(),
                value: resolved.storage_value.clone(),
                ttl: resolved.ttl,
                priority: resolved.priority,
                zone_id: zone.id,
                created_at: existing_record.created_at,
            };

            validate_record_update_constraints_normalized(
                &zone,
                &zone_records,
                &existing_record,
                &candidate_updated,
                &lookup_owner.stored_name,
            )?;
            candidate_updated.name = lookup_owner.stored_name;

            let new_serial = generate_serial(Some(zone.serial));
            let zone_name = zone.name.clone();

            let updated_record = RepositoryService::update_record_tx(&mut tx, candidate_updated)
                .await
                .map_err(|e| {
                    log_error!("Failed to update record: {}", e);
                    ServiceError::internal("Failed to update record".to_string())
                })?;

            // Increment zone serial so IXFR consumers can detect this change
            RepositoryService::update_zone_serial_tx(&mut tx, zone.id, new_serial)
                .await
                .map_err(|e| {
                    log_error!("Failed to update zone serial: {}", e);
                    ServiceError::internal("Failed to update zone serial".to_string())
                })?;

            // Record DEL(old)+ADD(new) zone changes for IXFR in one batch.
            let changes = vec![
                ZoneChange {
                    id: 0,
                    zone_id: zone.id,
                    serial: new_serial,
                    operation: "DEL".to_string(),
                    record_name: existing_record.name.clone(),
                    record_type: existing_record.record_type.to_string(),
                    record_value: existing_record.value.clone(),
                    record_ttl: existing_record.ttl,
                    record_priority: existing_record.priority,
                },
                ZoneChange {
                    id: 0,
                    zone_id: zone.id,
                    serial: new_serial,
                    operation: "ADD".to_string(),
                    record_name: updated_record.name.clone(),
                    record_type: updated_record.record_type.to_string(),
                    record_value: updated_record.value.clone(),
                    record_ttl: updated_record.ttl,
                    record_priority: updated_record.priority,
                },
            ];
            RepositoryService::create_zone_changes_tx(&mut tx, &changes)
                .await
                .map_err(|e| {
                    log_error!("Failed to create zone changes: {}", e);
                    ServiceError::internal("Failed to create zone change".to_string())
                })?;

            save_zone_snapshot_tx(&mut tx, &zone, new_serial).await?;

            Ok::<(Record, String), ServiceError>((updated_record, zone_name))
        }
        .await;

        let (updated_record, zone_name) =
            RepositoryService::finish_tx(tx, apply_result, "Failed to update record").await?;

        log_info!(
            "event=record_update zone={} name={} type={} ttl={} priority={} record_id={}",
            zone_name,
            updated_record.name,
            updated_record.record_type,
            updated_record
                .ttl
                .map_or("null".to_string(), |v| v.to_string()),
            updated_record
                .priority
                .map_or("null".to_string(), |v| v.to_string()),
            updated_record.id
        );

        if let Err(e) = crate::notify::send_notify_after_update(Some(&zone_name)).await {
            log_warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
        }

        Ok(RecordWithZone::new(updated_record, zone_name))
    }
}

fn parse_record_type(value: &str) -> Result<RecordType, ServiceError> {
    value
        .parse::<RecordType>()
        .map_err(|_| ServiceError::invalid_input(format!("Invalid record type: {}", value)))
}
