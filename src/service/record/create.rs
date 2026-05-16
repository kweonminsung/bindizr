use crate::{
    api::dto::CreateRecordRequest,
    database::model::{
        record::{Record, RecordType},
        zone_change::ZoneChange,
    },
    dns, log_error, log_info, log_warn,
    service::{
        RepositoryTx, error::ServiceError, repository::RepositoryService, utils::generate_serial,
        zone::snapshot::save_zone_snapshot_tx,
    },
};
use chrono::Utc;

use super::{RecordService, validation::validate_record_add_constraints};

impl RecordService {
    pub(crate) async fn create_tx(
        tx: &mut RepositoryTx<'_>,
        record: Record,
    ) -> Result<Record, ServiceError> {
        RepositoryService::create_record_tx(tx, record).await
    }

    pub async fn create(
        create_record_request: &CreateRecordRequest,
    ) -> Result<Record, ServiceError> {
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

        // Check if zone exists
        let zone = match RepositoryService::get_zone_by_name(&create_record_request.zone_name).await
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
            match RepositoryService::get_records_by_zone_id(zone.id).await {
                Ok(records) => records,
                Err(e) => {
                    log_error!("Failed to check existing records: {}", e);
                    return Err(ServiceError::Internal(
                        "Failed to create record".to_string(),
                    ));
                }
            };

        validate_record_add_constraints(
            &zone,
            &existing_records_in_zone,
            &create_record_request.name,
            &record_type,
            &create_record_request.value,
            None,
        )?;

        // Create record
        let mut tx = RepositoryService::begin_tx("Failed to create record").await?;

        let new_serial = generate_serial(Some(zone.serial));

        let apply_result = async {
            let created_record = RepositoryService::create_record_tx(
                &mut tx,
                Record {
                    id: 0, // Will be set by the database
                    name: create_record_request.name.clone(),
                    record_type,
                    value: create_record_request.value.clone(),
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
                    record_value: create_record_request.value.clone(),
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

            Ok::<Record, ServiceError>(created_record)
        }
        .await;

        let created_record =
            RepositoryService::finish_tx(tx, apply_result, "Failed to create record").await?;

        // Log record creation after commit
        log_info!(
            "event=record_create zone={} name={} type={} value={} ttl={} priority={} record_id={}",
            zone.name,
            create_record_request.name,
            create_record_request.record_type,
            create_record_request.value,
            create_record_request
                .ttl
                .map_or("null".to_string(), |v| v.to_string()),
            create_record_request
                .priority
                .map_or("null".to_string(), |v| v.to_string()),
            created_record.id
        );

        // Send NOTIFY to secondary servers
        if let Err(e) = dns::xfr::notify::send_notify(Some(&zone.name)).await {
            log_warn!("Failed to send NOTIFY for zone {}: {}", zone.name, e);
        }

        Ok(created_record)
    }
}
