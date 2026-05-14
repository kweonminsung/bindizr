use crate::{
    api::dto::CreateZoneRequest,
    database::model::{
        record::{Record, RecordType},
        zone::Zone,
        zone_change::ZoneChange,
    },
    dns, log_error, log_info, log_warn,
    service::{
        error::ServiceError,
        repository::RepositoryService,
        utils::{
            generate_serial, has_glue_records_for, is_in_bailiwick, to_fqdn, to_relative_domain,
        },
        zone::snapshot::save_zone_snapshot_tx,
    },
};
use chrono::Utc;

use super::ZoneService;

impl ZoneService {
    pub async fn update_zone(
        zone_name: &str,
        update_zone_request: &CreateZoneRequest,
    ) -> Result<Zone, ServiceError> {
        // Check if zone exists
        let existing_zone = match RepositoryService::get_zone_by_name(zone_name).await {
            Ok(Some(zone)) => zone,
            Ok(None) => {
                log_error!("Zone with name '{}' not found", zone_name);
                return Err(ServiceError::NotFound(format!(
                    "Zone with name '{}' not found",
                    zone_name
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err(ServiceError::Internal("Failed to update zone".to_string()));
            }
        };
        let zone_id = existing_zone.id;

        // Check if zone with the new name already exists (if name is being changed)
        if zone_name != update_zone_request.name {
            match RepositoryService::get_zone_by_name(&update_zone_request.name).await {
                Ok(Some(_)) => {
                    log_error!("Zone with name {} already exists", update_zone_request.name);
                    return Err(ServiceError::BadRequest(
                        "Zone with this name already exists".to_string(),
                    ));
                }
                Ok(None) => (),
                Err(e) => {
                    log_error!("Failed to check existing zone: {}", e);
                    return Err(ServiceError::Internal("Failed to update zone".to_string()));
                }
            };
        }

        // Auto-increment serial if not provided, or use existing if no change
        let new_serial = match update_zone_request.serial {
            Some(s) => s,
            None => generate_serial(Some(existing_zone.serial)),
        };

        let zone_records = RepositoryService::get_records_by_zone_id(zone_id)
            .await
            .map_err(|e| {
                log_error!("Failed to fetch zone records: {}", e);
                ServiceError::Internal("Failed to update zone".to_string())
            })?;

        if is_in_bailiwick(&update_zone_request.primary_ns, &update_zone_request.name) {
            let relative = to_relative_domain(
                &to_fqdn(&update_zone_request.primary_ns),
                &update_zone_request.name,
            );
            if !has_glue_records_for(&zone_records, &relative, None) {
                return Err(ServiceError::BadRequest(format!(
                    "Primary NS '{}' is in-bailiwick and requires at least one A/AAAA glue record for '{}'",
                    update_zone_request.primary_ns, relative
                )));
            }
        }

        // Update zone
        let mut tx = RepositoryService::begin_tx("Failed to update zone").await?;

        let apply_result = async {
            let updated_zone = RepositoryService::update_zone_tx(
                &mut tx,
                Zone {
                    id: zone_id,
                    name: update_zone_request.name.clone(),
                    primary_ns: update_zone_request.primary_ns.clone(),
                    admin_email: update_zone_request.admin_email.clone(),
                    ttl: update_zone_request.ttl,
                    serial: new_serial,
                    refresh: update_zone_request.refresh.unwrap_or(86400),
                    retry: update_zone_request.retry.unwrap_or(7200),
                    expire: update_zone_request.expire.unwrap_or(3_600_000),
                    minimum_ttl: update_zone_request.minimum_ttl.unwrap_or(86400),
                    created_at: Utc::now(), // Will be set by the database
                },
            )
            .await
            .map_err(|e| {
                log_error!("Failed to update zone: {}", e);
                ServiceError::Internal("Failed to update zone".to_string())
            })?;

            // Record zone changes for IXFR
            let has_primary_ns = zone_records.iter().any(|r| {
                r.record_type == RecordType::NS
                    && r.name == "@"
                    && to_fqdn(&r.value).eq_ignore_ascii_case(&to_fqdn(&updated_zone.primary_ns))
            });

            if !has_primary_ns {
                let primary_ns_record = Record {
                    id: 0,
                    name: "@".to_string(),
                    record_type: RecordType::NS,
                    value: updated_zone.primary_ns.clone(),
                    ttl: Some(updated_zone.ttl),
                    priority: None,
                    zone_id,
                    created_at: Utc::now(),
                };

                RepositoryService::create_record_tx(&mut tx, primary_ns_record)
                    .await
                    .map_err(|e| {
                        log_error!("Failed to create primary NS record during update: {}", e);
                        ServiceError::Internal("Failed to keep primary NS consistency".to_string())
                    })?;

                RepositoryService::create_zone_change_tx(
                    &mut tx,
                    ZoneChange {
                        id: 0,
                        zone_id,
                        serial: new_serial,
                        operation: "ADD".to_string(),
                        record_name: "@".to_string(),
                        record_type: "NS".to_string(),
                        record_value: updated_zone.primary_ns.clone(),
                        record_ttl: Some(updated_zone.ttl),
                        record_priority: None,
                    },
                )
                .await
                .map_err(|e| {
                    log_error!("Failed to create zone change (ADD NS): {}", e);
                    ServiceError::Internal("Failed to create zone change".to_string())
                })?;
            }

            let format_soa = |zone: &Zone| -> String {
                format!(
                    "{} {} {} {} {} {} {}",
                    zone.primary_ns,
                    zone.admin_email.replace('@', "."),
                    zone.serial,
                    zone.refresh,
                    zone.retry,
                    zone.expire,
                    zone.minimum_ttl
                )
            };

            // Delete old SOA record
            RepositoryService::create_zone_change_tx(
                &mut tx,
                ZoneChange {
                    id: 0,
                    zone_id,
                    serial: new_serial,
                    operation: "DEL".to_string(),
                    record_name: "@".to_string(),
                    record_type: "SOA".to_string(),
                    record_value: format_soa(&existing_zone),
                    record_ttl: Some(existing_zone.ttl),
                    record_priority: None,
                },
            )
            .await
            .map_err(|e| {
                log_error!("Failed to create zone change (DEL SOA): {}", e);
                ServiceError::Internal("Failed to create zone change".to_string())
            })?;

            // Add new SOA record
            RepositoryService::create_zone_change_tx(
                &mut tx,
                ZoneChange {
                    id: 0,
                    zone_id,
                    serial: new_serial,
                    operation: "ADD".to_string(),
                    record_name: "@".to_string(),
                    record_type: "SOA".to_string(),
                    record_value: format_soa(&updated_zone),
                    record_ttl: Some(updated_zone.ttl),
                    record_priority: None,
                },
            )
            .await
            .map_err(|e| {
                log_error!("Failed to create zone change (ADD SOA): {}", e);
                ServiceError::Internal("Failed to create zone change".to_string())
            })?;

            save_zone_snapshot_tx(&mut tx, &updated_zone, new_serial).await?;

            Ok::<Zone, ServiceError>(updated_zone)
        }
        .await;

        let updated_zone =
            RepositoryService::finish_tx(tx, apply_result, "Failed to update zone").await?;

        // Log zone update after commit (structured logging)
        log_info!(
            "event=zone_update zone={} previous_name={} new_serial={} zone_id={}",
            update_zone_request.name,
            zone_name,
            new_serial,
            updated_zone.id
        );

        // Send NOTIFY to secondary servers
        if let Err(e) = dns::xfr::notify::send_notify(Some(&updated_zone.name)).await {
            log_warn!(
                "Failed to send NOTIFY for zone {}: {}",
                updated_zone.name,
                e
            );
        }

        Ok(updated_zone)
    }
}
