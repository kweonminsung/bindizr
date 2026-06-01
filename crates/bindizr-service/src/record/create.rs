use crate::{
    RepositoryTx,
    error::ServiceError,
    log_error, log_info, log_warn,
    model::{
        record::{Record, RecordType, RecordWithZone},
        zone_change::ZoneChange,
    },
    repository::RepositoryService,
    types::CreateRecordRequest,
    utils::generate_serial,
    zone::snapshot::save_zone_snapshot_tx,
};
use chrono::Utc;

use super::{RecordService, validation::validate_record_add_constraints};

impl RecordService {
    pub async fn create_tx(
        tx: &mut RepositoryTx<'_>,
        record: Record,
    ) -> Result<Record, ServiceError> {
        RepositoryService::create_record_tx(tx, record).await
    }

    pub async fn create(
        create_record_request: &CreateRecordRequest,
    ) -> Result<RecordWithZone, ServiceError> {
        // Validate record type
        let record_type = create_record_request
            .record_type
            .parse::<RecordType>()
            .map_err(|_| {
                ServiceError::BadRequest(format!(
                    "Invalid record type: {}",
                    create_record_request.record_type
                ))
            })?;
        let record_value = create_record_request
            .value
            .to_storage_value(&record_type)
            .map_err(ServiceError::BadRequest)?;

        let mut tx = RepositoryService::begin_tx("Failed to create record").await?;

        let apply_result = async {
            let zone = match RepositoryService::get_zone_by_name_tx(
                &mut tx,
                &create_record_request.zone_name,
            )
            .await
            {
                Ok(Some(zone)) => zone,
                Ok(None) => {
                    return Err(ServiceError::NotFound(format!(
                        "Zone with name '{}' not found",
                        create_record_request.zone_name
                    )));
                }
                Err(e) => {
                    log_error!("Failed to fetch zone: {}", e);
                    return Err(ServiceError::Internal(
                        "Failed to create record".to_string(),
                    ));
                }
            };

            let existing_records_in_zone =
                match RepositoryService::get_records_by_zone_id_tx(&mut tx, zone.id).await {
                    Ok(records) => records,
                    Err(e) => {
                        log_error!("Failed to check existing records: {}", e);
                        return Err(ServiceError::Internal(
                            "Failed to create record".to_string(),
                        ));
                    }
                };

            let normalized_owner = validate_record_add_constraints(
                &zone,
                &existing_records_in_zone,
                &create_record_request.name,
                &record_type,
                &record_value,
                create_record_request.priority,
                None,
            )?;

            let new_serial = generate_serial(Some(zone.serial));
            let zone_name = zone.name.clone();

            let created_record = RepositoryService::create_record_tx(
                &mut tx,
                Record {
                    id: 0, // Will be set by the database
                    name: normalized_owner.stored_name,
                    record_type,
                    value: record_value.clone(),
                    ttl: create_record_request.ttl,
                    priority: create_record_request.priority,
                    zone_id: zone.id,
                    created_at: Utc::now(), // Will be set by the database
                },
            )
            .await
            .map_err(|e| {
                log_error!("Failed to create record: {}", e);
                ServiceError::Internal("Failed to create record".to_string())
            })?;

            // Increment zone serial so IXFR consumers can detect this change
            RepositoryService::update_zone_tx(
                &mut tx,
                crate::model::zone::Zone {
                    serial: new_serial,
                    ..zone.clone()
                },
            )
            .await
            .map_err(|e| {
                log_error!("Failed to update zone serial: {}", e);
                ServiceError::Internal("Failed to update zone serial".to_string())
            })?;

            // Record zone change for IXFR
            RepositoryService::create_zone_change_tx(
                &mut tx,
                ZoneChange {
                    id: 0,
                    zone_id: zone.id,
                    serial: new_serial,
                    operation: "ADD".to_string(),
                    record_name: created_record.name.clone(),
                    record_type: create_record_request.record_type.clone(),
                    record_value: created_record.value.clone(),
                    record_ttl: create_record_request.ttl,
                    record_priority: create_record_request.priority,
                },
            )
            .await
            .map_err(|e| {
                log_error!("Failed to create zone change: {}", e);
                ServiceError::Internal("Failed to create zone change".to_string())
            })?;

            save_zone_snapshot_tx(&mut tx, &zone, new_serial).await?;

            Ok::<(Record, String), ServiceError>((created_record, zone_name))
        }
        .await;

        let (created_record, zone_name) =
            RepositoryService::finish_tx(tx, apply_result, "Failed to create record").await?;

        // Log record creation after commit
        log_info!(
            "event=record_create zone={} name={} type={} ttl={} priority={} record_id={}",
            zone_name,
            create_record_request.name,
            create_record_request.record_type,
            create_record_request
                .ttl
                .map_or("null".to_string(), |v| v.to_string()),
            create_record_request
                .priority
                .map_or("null".to_string(), |v| v.to_string()),
            created_record.id
        );

        // Send NOTIFY to secondary servers
        if let Err(e) = crate::notify::send_notify(Some(&zone_name)).await {
            log_warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
        }

        Ok(RecordWithZone::new(created_record, zone_name))
    }
}
