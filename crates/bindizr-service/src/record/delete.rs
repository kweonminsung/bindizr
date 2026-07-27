use super::{RecordService, validation::validate_delete_constraints};
use crate::{
    RepositoryTx,
    error::{ErrorCode, ServiceError},
    log_error, log_info, log_warn,
    repository::RepositoryService,
    serial::generate_serial,
    zone::snapshot::save_zone_snapshot_tx,
};

/// Identity of the deleted record, carried out of the transaction for logging.
struct DeletedRecord {
    zone_name: String,
    record_name: String,
    record_type: String,
    record_value: String,
    record_id: i32,
}

impl RecordService {
    /// Delete a record by id within the caller's transaction.
    pub async fn delete_tx(tx: &mut RepositoryTx<'_>, record_id: i32) -> Result<(), ServiceError> {
        RepositoryService::delete_record_tx(tx, record_id).await
    }

    /// Delete a record by id, bumping the zone serial and recording a DEL change for IXFR.
    pub async fn delete_by_id(record_id: i32) -> Result<(), ServiceError> {
        // Resolve zone_id with a non-locking read so the tx locks zone before
        // record (the create/bulk/import order); the reverse can deadlock.
        let zone_id = match RepositoryService::get_record_by_id(record_id).await {
            Ok(Some(record)) => record.zone_id,
            Ok(None) => {
                return Err(ServiceError::record_not_found(record_id));
            }
            Err(e) => {
                log_error!("Failed to fetch record: {}", e);
                return Err(ServiceError::internal("Failed to fetch record".to_string()));
            }
        };

        let mut tx = RepositoryService::begin_tx("Failed to delete record").await?;

        let apply_result: Result<DeletedRecord, ServiceError> = async {
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

            let new_serial = generate_serial(Some(zone.serial))?;

            validate_delete_constraints(&zone, std::slice::from_ref(&existing_record))?;

            RepositoryService::delete_record_tx(&mut tx, record_id)
                .await
                .map_err(|e| {
                    log_error!("Failed to delete record: {}", e);
                    ServiceError::internal("Failed to delete record".to_string())
                })?;

            // Increment zone serial so IXFR consumers can detect this change
            RepositoryService::update_zone_serial_tx(&mut tx, zone.id, new_serial)
                .await
                .map_err(|e| {
                    log_error!("Failed to update zone serial: {}", e);
                    ServiceError::internal("Failed to update zone serial".to_string())
                })?;

            // Record zone change for IXFR
            RepositoryService::create_zone_change_tx(
                &mut tx,
                crate::model::zone_change::ZoneChange {
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
            )
            .await
            .map_err(|e| {
                log_error!("Failed to create zone change: {}", e);
                ServiceError::internal("Failed to create zone change".to_string())
            })?;

            save_zone_snapshot_tx(&mut tx, &zone, new_serial).await?;

            Ok(DeletedRecord {
                zone_name: zone.name,
                record_name: existing_record.name,
                record_type: existing_record.record_type.to_string(),
                record_value: existing_record.value,
                record_id: existing_record.id,
            })
        }
        .await;

        let DeletedRecord {
            zone_name,
            record_name,
            record_type,
            record_value,
            record_id,
        } = RepositoryService::finish_tx(tx, apply_result, "Failed to delete record").await?;

        log_info!(
            "event=record_delete zone={} name={} type={} value={} record_id={}",
            zone_name,
            record_name,
            record_type,
            record_value,
            record_id
        );

        if let Err(e) = crate::notify::send_notify_after_update(Some(&zone_name)).await {
            log_warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
        }

        Ok(())
    }
}
