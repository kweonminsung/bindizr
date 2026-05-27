use crate::{
    database::model::{
        record::{Record, RecordType},
        zone_change::ZoneChange,
    },
    dto::UpdateRecordRequest,
    log_error, log_info, log_warn,
    service::{
        error::ServiceError, repository::RepositoryService, utils::generate_serial,
        zone::snapshot::save_zone_snapshot_tx,
    },
};

use super::{RecordService, validation::validate_record_update_constraints};

impl RecordService {
    pub async fn update_by_id(
        record_id: i32,
        update_record_request: &UpdateRecordRequest,
    ) -> Result<Record, ServiceError> {
        let zone_id = match RepositoryService::get_record_by_id(record_id).await {
            Ok(Some(record)) => record.zone_id,
            Ok(None) => {
                return Err(ServiceError::NotFound(format!(
                    "Record with id '{}' not found",
                    record_id
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch record: {}", e);
                return Err(ServiceError::Internal("Failed to fetch record".to_string()));
            }
        };

        let mut tx = RepositoryService::begin_tx("Failed to update record").await?;

        let apply_result = async {
            let zone = match RepositoryService::get_zone_by_id_tx(&mut tx, zone_id).await {
                Ok(Some(zone)) => zone,
                Ok(None) => {
                    return Err(ServiceError::NotFound(format!(
                        "Zone with id '{}' not found",
                        zone_id
                    )));
                }
                Err(e) => {
                    log_error!("Failed to fetch zone: {}", e);
                    return Err(ServiceError::Internal("Failed to fetch zone".to_string()));
                }
            };

            let existing_record =
                match RepositoryService::get_record_by_id_tx(&mut tx, record_id).await {
                    Ok(Some(record)) if record.zone_id == zone.id => record,
                    Ok(Some(_)) | Ok(None) => {
                        return Err(ServiceError::NotFound(format!(
                            "Record with id '{}' not found",
                            record_id
                        )));
                    }
                    Err(e) => {
                        log_error!("Failed to fetch record: {}", e);
                        return Err(ServiceError::Internal("Failed to fetch record".to_string()));
                    }
                };

            let record_type = update_record_request
                .record_type
                .parse::<RecordType>()
                .map_err(|_| {
                    ServiceError::BadRequest(format!(
                        "Invalid record type: {}",
                        update_record_request.record_type
                    ))
                })?;
            let record_value = update_record_request
                .value
                .to_storage_value(&record_type)
                .map_err(ServiceError::BadRequest)?;

            let zone_records =
                match RepositoryService::get_records_by_zone_id_tx(&mut tx, zone.id).await {
                    Ok(records) => records,
                    Err(e) => {
                        log_error!("Failed to load zone records: {}", e);
                        return Err(ServiceError::Internal(
                            "Failed to update record".to_string(),
                        ));
                    }
                };

            let candidate_updated = Record {
                id: existing_record.id,
                name: update_record_request.name.clone(),
                record_type: record_type.clone(),
                value: record_value,
                ttl: update_record_request.ttl,
                priority: update_record_request.priority,
                zone_id: zone.id,
                created_at: existing_record.created_at,
            };

            validate_record_update_constraints(
                &zone,
                &zone_records,
                &existing_record,
                &candidate_updated,
            )?;

            let new_serial = generate_serial(Some(zone.serial));
            let zone_name = zone.name.clone();

            let updated_record = RepositoryService::update_record_tx(&mut tx, candidate_updated)
                .await
                .map_err(|e| {
                    log_error!("Failed to update record: {}", e);
                    ServiceError::Internal("Failed to update record".to_string())
                })?;

            // Increment zone serial so IXFR consumers can detect this change
            RepositoryService::update_zone_tx(
                &mut tx,
                crate::database::model::zone::Zone {
                    serial: new_serial,
                    ..zone.clone()
                },
            )
            .await
            .map_err(|e| {
                log_error!("Failed to update zone serial: {}", e);
                ServiceError::Internal("Failed to update zone serial".to_string())
            })?;

            // Record zone changes for IXFR

            // Delete old record
            RepositoryService::create_zone_change_tx(
                &mut tx,
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
            )
            .await
            .map_err(|e| {
                log_error!("Failed to create zone change (DEL): {}", e);
                ServiceError::Internal("Failed to create zone change".to_string())
            })?;

            // Add new record
            RepositoryService::create_zone_change_tx(
                &mut tx,
                ZoneChange {
                    id: 0,
                    zone_id: zone.id,
                    serial: new_serial,
                    operation: "ADD".to_string(),
                    record_name: updated_record.name.clone(),
                    record_type: updated_record.record_type.to_string(),
                    record_value: updated_record.value.clone(),
                    record_ttl: update_record_request.ttl,
                    record_priority: update_record_request.priority,
                },
            )
            .await
            .map_err(|e| {
                log_error!("Failed to create zone change (ADD): {}", e);
                ServiceError::Internal("Failed to create zone change".to_string())
            })?;

            save_zone_snapshot_tx(&mut tx, &zone, new_serial).await?;

            Ok::<(Record, String), ServiceError>((updated_record, zone_name))
        }
        .await;

        let (updated_record, zone_name) =
            RepositoryService::finish_tx(tx, apply_result, "Failed to update record").await?;

        // Log record update after commit
        log_info!(
            "event=record_update zone={} name={} type={} ttl={} priority={} record_id={}",
            zone_name,
            update_record_request.name,
            update_record_request.record_type,
            update_record_request
                .ttl
                .map_or("null".to_string(), |v| v.to_string()),
            update_record_request
                .priority
                .map_or("null".to_string(), |v| v.to_string()),
            updated_record.id
        );

        // Send NOTIFY to secondary servers
        if let Err(e) = crate::service::notify::send_notify(Some(&zone_name)).await {
            log_warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
        }

        Ok(updated_record)
    }
}
