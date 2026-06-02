use crate::{
    error::ServiceError,
    log_error, log_info, log_warn,
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    repository::RepositoryService,
    serial::generate_serial,
    types::CreateZoneRequest,
    zone::{
        snapshot::save_zone_snapshot_tx,
        validation::{is_same_zone_name, validate_create_zone_request},
    },
};
use chrono::Utc;

use super::ZoneService;

impl ZoneService {
    pub async fn create(create_zone_request: &CreateZoneRequest) -> Result<Zone, ServiceError> {
        let validated = validate_create_zone_request(create_zone_request)?;

        // Parent/child zones are allowed; only the same normalized zone name is rejected.
        match RepositoryService::get_all_zones().await {
            Ok(zones) => {
                if zones
                    .iter()
                    .any(|zone| is_same_zone_name(&zone.name, &validated.name_fqdn))
                {
                    log_error!("Zone with name {} already exists", validated.name);
                    return Err(ServiceError::BadRequest(
                        "zone name already exists".to_string(),
                    ));
                }
            }
            Err(e) => {
                log_error!("Failed to check existing zone: {}", e);
                return Err(ServiceError::Internal("Failed to create zone".to_string()));
            }
        };

        // Generate serial if not provided
        let serial = match create_zone_request.serial {
            Some(s) => s,
            None => generate_serial(None),
        };

        // Create zone
        let mut tx = RepositoryService::begin_tx("Failed to create zone").await?;

        let apply_result = async {
            let created_zone = RepositoryService::create_zone_tx(
                &mut tx,
                Zone {
                    id: 0, // Will be set by the database
                    name: validated.name.clone(),
                    primary_ns: validated.primary_ns.clone(),
                    admin_email: validated.admin_email.clone(),
                    ttl: validated.ttl,
                    serial,
                    refresh: create_zone_request.refresh.unwrap_or(86400),
                    retry: create_zone_request.retry.unwrap_or(7200),
                    expire: create_zone_request.expire.unwrap_or(3_600_000),
                    minimum_ttl: create_zone_request.minimum_ttl.unwrap_or(86400),
                    created_at: Utc::now(), // Will be set by the database
                },
            )
            .await
            .map_err(|e| {
                log_error!("Failed to create zone: {}", e);
                ServiceError::Internal("Failed to create zone".to_string())
            })?;

            // Keep zones.primary_ns aligned with at least one apex NS record in records table.
            let primary_ns_apex_record = Record {
                id: 0,
                name: "@".to_string(),
                record_type: RecordType::NS,
                value: validated.primary_ns.clone(),
                ttl: Some(validated.ttl),
                priority: None,
                zone_id: created_zone.id,
                created_at: Utc::now(),
            };

            RepositoryService::create_record_tx(&mut tx, primary_ns_apex_record)
                .await
                .map_err(|e| {
                    log_error!("Failed to create primary NS record: {}", e);
                    ServiceError::Internal("Failed to create primary NS record".to_string())
                })?;

            save_zone_snapshot_tx(&mut tx, &created_zone, created_zone.serial).await?;

            Ok::<Zone, ServiceError>(created_zone)
        }
        .await;

        let created_zone =
            RepositoryService::finish_tx(tx, apply_result, "Failed to create zone").await?;

        // Log zone creation after commit (structured logging)
        log_info!(
            "event=zone_create zone={} primary_ns={} serial={} zone_id={}",
            created_zone.name,
            created_zone.primary_ns,
            created_zone.serial,
            created_zone.id
        );

        if let Err(e) = crate::notify::send_notify(Some("catalog.bind")).await {
            log_warn!("Failed to send NOTIFY for catalog.bind: {}", e);
        }

        Ok(created_zone)
    }
}
