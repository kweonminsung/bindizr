use crate::{
    database::model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    dto::CreateZoneRequest,
    log_error, log_info,
    service::{
        error::ServiceError, repository::RepositoryService, utils::generate_serial,
        zone::snapshot::save_zone_snapshot_tx,
    },
};
use chrono::Utc;

use super::ZoneService;

impl ZoneService {
    pub async fn create(create_zone_request: &CreateZoneRequest) -> Result<Zone, ServiceError> {
        // Check if zone already exists
        match RepositoryService::get_zone_by_name(&create_zone_request.name).await {
            Ok(Some(_)) => {
                log_error!("Zone with name {} already exists", create_zone_request.name);
                return Err(ServiceError::BadRequest(
                    "Zone with this name already exists".to_string(),
                ));
            }
            Ok(None) => (),
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
                    name: create_zone_request.name.clone(),
                    primary_ns: create_zone_request.primary_ns.clone(),
                    admin_email: create_zone_request.admin_email.clone(),
                    ttl: create_zone_request.ttl,
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
                value: create_zone_request.primary_ns.clone(),
                ttl: Some(create_zone_request.ttl),
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

        Ok(created_zone)
    }
}
