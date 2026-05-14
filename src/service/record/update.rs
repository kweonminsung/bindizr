use crate::{
    api::dto::CreateRecordRequest,
    database::model::{
        record::{Record, RecordType},
        zone_change::ZoneChange,
    },
    dns, log_error, log_info, log_warn,
    service::{
        error::ServiceError,
        repository::RepositoryService,
        utils::{generate_serial, is_apex_name, to_fqdn},
        zone::snapshot::save_zone_snapshot_tx,
    },
};
use chrono::Utc;

use super::{
    RecordService,
    validation::{validate_glue_invariants, validate_record_add_constraints},
};

impl RecordService {
    pub async fn update_record(
        name: &str,
        record_type_str: &str,
        update_record_request: &CreateRecordRequest,
    ) -> Result<Record, ServiceError> {
        // Validate old record type
        let old_record_type = RecordType::from_str(record_type_str).map_err(|_| {
            ServiceError::BadRequest(format!("Invalid record type: {}", record_type_str))
        })?;

        // Check if record exists
        let existing_record =
            match RepositoryService::get_record_by_name_and_type(name, &old_record_type).await {
                Ok(Some(record)) => record,
                Ok(None) => {
                    return Err(ServiceError::NotFound(format!(
                        "Record with name '{}' and type '{}' not found",
                        name, record_type_str
                    )));
                }
                Err(e) => {
                    log_error!("Failed to fetch record: {}", e);
                    return Err(ServiceError::Internal("Failed to fetch record".to_string()));
                }
            };

        let record_id = existing_record.id;

        // Load authoritative zone from the existing record to avoid cross-zone mismatches.
        let zone = match RepositoryService::get_zone_by_id(existing_record.zone_id).await {
            Ok(Some(zone)) => zone,
            Ok(None) => {
                return Err(ServiceError::Internal("Failed to fetch zone".to_string()));
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err(ServiceError::Internal("Failed to fetch zone".to_string()));
            }
        };

        if zone.name != update_record_request.zone_name {
            return Err(ServiceError::BadRequest(format!(
                "Record belongs to zone '{}', but request zone is '{}'",
                zone.name, update_record_request.zone_name
            )));
        }

        // Validate record type
        let record_type =
            RecordType::from_str(&update_record_request.record_type).map_err(|_| {
                ServiceError::BadRequest(format!(
                    "Invalid record type: {}",
                    update_record_request.record_type
                ))
            })?;

        // Preserve previous API semantics for SOA update attempts.
        if record_type == RecordType::SOA {
            log_error!("Cannot update to SOA record type");
            return Err(ServiceError::BadRequest(
                "Cannot update to SOA record type".to_string(),
            ));
        }

        let zone_records = match RepositoryService::get_records_by_zone_id(zone.id).await {
            Ok(records) => records,
            Err(e) => {
                log_error!("Failed to load zone records: {}", e);
                return Err(ServiceError::Internal(
                    "Failed to update record".to_string(),
                ));
            }
        };

        // Note: HTTP update has one extra invariant (primary_ns NS immutability) checked below.
        // The rest of the DNS integrity checks are shared with NSUPDATE.
        validate_record_add_constraints(
            &zone,
            &zone_records,
            &update_record_request.name,
            &record_type,
            &update_record_request.value,
            Some(record_id),
        )?;

        // Updating a record is effectively DEL(old) + ADD(new). Ensure the resulting zone doesn't
        // lose mandatory glue for any remaining in-bailiwick apex NS records.
        let candidate_updated = Record {
            id: record_id,
            name: update_record_request.name.clone(),
            record_type: record_type.clone(),
            value: update_record_request.value.clone(),
            ttl: update_record_request.ttl,
            priority: update_record_request.priority,
            zone_id: zone.id,
            created_at: existing_record.created_at,
        };

        let records_after_update: Vec<Record> = zone_records
            .iter()
            .map(|r| {
                if r.id == record_id {
                    candidate_updated.clone()
                } else {
                    r.clone()
                }
            })
            .collect();

        validate_glue_invariants(&zone, &records_after_update)?;

        if existing_record.record_type == RecordType::NS
            && is_apex_name(&existing_record.name, &zone.name)
            && to_fqdn(&existing_record.value).eq_ignore_ascii_case(&to_fqdn(&zone.primary_ns))
        {
            let still_primary = record_type == RecordType::NS
                && is_apex_name(&update_record_request.name, &zone.name)
                && to_fqdn(&update_record_request.value)
                    .eq_ignore_ascii_case(&to_fqdn(&zone.primary_ns));

            if !still_primary {
                return Err(ServiceError::BadRequest(
                    "Cannot modify the NS record referenced by zone primary_ns".to_string(),
                ));
            }
        }

        // NS constraints are already covered by validate_record_add_constraints.

        // Update record
        let mut tx = RepositoryService::begin_tx("Failed to update record").await?;

        let new_serial = generate_serial(Some(zone.serial));

        let apply_result = async {
            let updated_record = RepositoryService::update_record_tx(
                &mut tx,
                Record {
                    id: record_id,
                    name: update_record_request.name.clone(),
                    record_type,
                    value: update_record_request.value.clone(),
                    ttl: update_record_request.ttl,
                    priority: update_record_request.priority,
                    zone_id: zone.id,
                    created_at: Utc::now(), // Will be set by the database
                },
            )
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
                    record_type: update_record_request.record_type.clone(),
                    record_value: update_record_request.value.clone(),
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

            Ok::<Record, ServiceError>(updated_record)
        }
        .await;

        let updated_record =
            RepositoryService::finish_tx(tx, apply_result, "Failed to update record").await?;

        // Log record update after commit
        log_info!(
            "event=record_update zone={} name={} type={} old_value={} new_value={} ttl={} priority={} record_id={}",
            zone.name,
            update_record_request.name,
            update_record_request.record_type,
            existing_record.value,
            update_record_request.value,
            update_record_request
                .ttl
                .map_or("null".to_string(), |v| v.to_string()),
            update_record_request
                .priority
                .map_or("null".to_string(), |v| v.to_string()),
            updated_record.id
        );

        // Send NOTIFY to secondary servers
        if let Err(e) = dns::xfr::notify::send_notify(Some(&zone.name)).await {
            log_warn!("Failed to send NOTIFY for zone {}: {}", zone.name, e);
        }

        Ok(updated_record)
    }
}
