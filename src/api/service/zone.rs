use crate::{
    api::{dto::CreateZoneRequest, error::ApiError},
    database::{
        error::DatabaseError,
        get_zone_change_repository, get_zone_repository,
        model::{zone::Zone, zone_change::ZoneChange},
    },
    log_error, log_info, log_warn, xfr,
};
use chrono::Utc;

/// Generate next serial number in YYYYMMDDNN format
fn generate_serial(current_serial: Option<i32>) -> i32 {
    let now = Utc::now();
    let date_prefix = now.format("%Y%m%d").to_string().parse::<i32>().unwrap();
    let base_serial = date_prefix * 100;

    match current_serial {
        Some(serial) => {
            // If same day, increment NN part
            if serial / 100 == date_prefix {
                serial + 1
            } else {
                // New day, reset to NN=00
                base_serial
            }
        }
        None => base_serial,
    }
}

#[derive(Clone)]
pub struct ZoneService;

impl ZoneService {
    pub async fn get_zones() -> Result<Vec<Zone>, ApiError> {
        let zone_repository = get_zone_repository();

        zone_repository.get_all().await.map_err(|e: DatabaseError| {
            log_error!("Failed to fetch zones: {}", e);
            ApiError::InternalServerError("Failed to fetch zones".to_string())
        })
    }

    pub async fn get_zone(zone_name: &str) -> Result<Zone, ApiError> {
        let zone_repository = get_zone_repository();

        match zone_repository.get_by_name(zone_name).await {
            Ok(Some(zone)) => Ok(zone),
            Ok(None) => Err(ApiError::NotFound(format!(
                "Zone with name '{}' not found",
                zone_name
            ))),
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                Err(ApiError::InternalServerError(
                    "Failed to fetch zone".to_string(),
                ))
            }
        }
    }

    pub async fn create_zone(create_zone_request: &CreateZoneRequest) -> Result<Zone, ApiError> {
        let zone_repository = get_zone_repository();

        // Validate that at least one of primary_ns_ip or primary_ns_ipv6 is present
        if create_zone_request.primary_ns_ip.is_none()
            && create_zone_request.primary_ns_ipv6.is_none()
        {
            return Err(ApiError::BadRequest(
                "At least one of primary_ns_ip or primary_ns_ipv6 must be provided".to_string(),
            ));
        }

        // Check if zone already exists
        match zone_repository.get_by_name(&create_zone_request.name).await {
            Ok(Some(_)) => {
                log_error!("Zone with name {} already exists", create_zone_request.name);
                return Err(ApiError::BadRequest(
                    "Zone with this name already exists".to_string(),
                ));
            }
            Ok(None) => (),
            Err(e) => {
                log_error!("Failed to check existing zone: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to create zone".to_string(),
                ));
            }
        };

        // Generate serial if not provided
        let serial = match create_zone_request.serial {
            Some(s) => s,
            None => generate_serial(None),
        };

        // Create zone
        let created_zone = zone_repository
            .create(Zone {
                id: 0, // Will be set by the database
                name: create_zone_request.name.clone(),
                primary_ns: create_zone_request.primary_ns.clone(),
                primary_ns_ip: create_zone_request.primary_ns_ip.clone(),
                primary_ns_ipv6: create_zone_request.primary_ns_ipv6.clone(),
                admin_email: create_zone_request.admin_email.clone(),
                ttl: create_zone_request.ttl,
                serial,
                refresh: create_zone_request.refresh.unwrap_or(86400),
                retry: create_zone_request.retry.unwrap_or(7200),
                expire: create_zone_request.expire.unwrap_or(3_600_000),
                minimum_ttl: create_zone_request.minimum_ttl.unwrap_or(86400),
                created_at: Utc::now(), // Will be set by the database
            })
            .await
            .map_err(|e: DatabaseError| {
                log_error!("Failed to create zone: {}", e);
                ApiError::InternalServerError("Failed to create zone".to_string())
            })?;

        // Log zone creation (structured logging)
        log_info!(
            "event=zone_create zone={} primary_ns={} admin_email={} serial={} zone_id={}",
            created_zone.name,
            created_zone.primary_ns,
            created_zone.admin_email,
            created_zone.serial,
            created_zone.id
        );

        Ok(created_zone)
    }

    pub async fn update_zone(
        zone_name: &str,
        update_zone_request: &CreateZoneRequest,
    ) -> Result<Zone, ApiError> {
        let zone_repository = get_zone_repository();

        // Validate that at least one of primary_ns_ip or primary_ns_ipv6 is present
        if update_zone_request.primary_ns_ip.is_none()
            && update_zone_request.primary_ns_ipv6.is_none()
        {
            return Err(ApiError::BadRequest(
                "At least one of primary_ns_ip or primary_ns_ipv6 must be provided".to_string(),
            ));
        }

        // Check if zone exists
        let existing_zone = match zone_repository.get_by_name(zone_name).await {
            Ok(Some(zone)) => zone,
            Ok(None) => {
                log_error!("Zone with name '{}' not found", zone_name);
                return Err(ApiError::NotFound(format!(
                    "Zone with name '{}' not found",
                    zone_name
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to update zone".to_string(),
                ));
            }
        };
        let zone_id = existing_zone.id;

        // Check if zone with the new name already exists (if name is being changed)
        if zone_name != update_zone_request.name {
            match zone_repository.get_by_name(&update_zone_request.name).await {
                Ok(Some(_)) => {
                    log_error!("Zone with name {} already exists", update_zone_request.name);
                    return Err(ApiError::BadRequest(
                        "Zone with this name already exists".to_string(),
                    ));
                }
                Ok(None) => (),
                Err(e) => {
                    log_error!("Failed to check existing zone: {}", e);
                    return Err(ApiError::InternalServerError(
                        "Failed to update zone".to_string(),
                    ));
                }
            };
        }

        // Auto-increment serial if not provided, or use existing if no change
        let new_serial = match update_zone_request.serial {
            Some(s) => s,
            None => generate_serial(Some(existing_zone.serial)),
        };

        // Update zone
        let updated_zone = zone_repository
            .update(Zone {
                id: zone_id,
                name: update_zone_request.name.clone(),
                primary_ns: update_zone_request.primary_ns.clone(),
                primary_ns_ip: update_zone_request.primary_ns_ip.clone(),
                primary_ns_ipv6: update_zone_request.primary_ns_ipv6.clone(),
                admin_email: update_zone_request.admin_email.clone(),
                ttl: update_zone_request.ttl,
                serial: new_serial,
                refresh: update_zone_request.refresh.unwrap_or(86400),
                retry: update_zone_request.retry.unwrap_or(7200),
                expire: update_zone_request.expire.unwrap_or(3_600_000),
                minimum_ttl: update_zone_request.minimum_ttl.unwrap_or(86400),
                created_at: Utc::now(), // Will be set by the database
            })
            .await
            .map_err(|e: DatabaseError| {
                log_error!("Failed to update zone: {}", e);
                ApiError::InternalServerError("Failed to update zone".to_string())
            })?;

        // Log zone update (structured logging)
        log_info!(
            "event=zone_update zone={} previous_name={} new_serial={} zone_id={}",
            update_zone_request.name,
            zone_name,
            new_serial,
            updated_zone.id
        );

        // Record zone changes for IXFR
        let zone_change_repository = get_zone_change_repository();

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
        zone_change_repository
            .create(ZoneChange {
                id: 0,
                zone_id,
                serial: new_serial,
                operation: "DEL".to_string(),
                record_name: "@".to_string(),
                record_type: "SOA".to_string(),
                record_value: format_soa(&existing_zone),
                record_ttl: Some(existing_zone.ttl),
                record_priority: None,
            })
            .await
            .map_err(|e| {
                log_error!("Failed to create zone change (DEL SOA): {}", e);
                ApiError::InternalServerError("Failed to create zone change".to_string())
            })?;

        // Add new SOA record
        zone_change_repository
            .create(ZoneChange {
                id: 0,
                zone_id,
                serial: new_serial,
                operation: "ADD".to_string(),
                record_name: "@".to_string(),
                record_type: "SOA".to_string(),
                record_value: format_soa(&updated_zone),
                record_ttl: Some(updated_zone.ttl),
                record_priority: None,
            })
            .await
            .map_err(|e| {
                log_error!("Failed to create zone change (ADD SOA): {}", e);
                ApiError::InternalServerError("Failed to create zone change".to_string())
            })?;

        // Send NOTIFY to secondary servers
        if let Err(e) = xfr::notify::send_notify(&updated_zone.name).await {
            log_warn!(
                "Failed to send NOTIFY for zone {}: {}",
                updated_zone.name,
                e
            );
        }

        Ok(updated_zone)
    }

    pub async fn delete_zone(zone_name: &str) -> Result<(), ApiError> {
        let zone_repository = get_zone_repository();

        // Check if zone exists and get its ID
        let zone = match zone_repository.get_by_name(zone_name).await {
            Ok(Some(z)) => z,
            Ok(None) => {
                log_error!("Zone with name '{}' not found", zone_name);
                return Err(ApiError::NotFound(format!(
                    "Zone with name '{}' not found",
                    zone_name
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to delete zone".to_string(),
                ));
            }
        };

        let zone_id = zone.id;
        let zone_name_clone = zone.name.clone();

        // Delete zone
        zone_repository
            .delete(zone_id)
            .await
            .map_err(|e: DatabaseError| {
                log_error!("Failed to delete zone: {}", e);
                ApiError::InternalServerError("Failed to delete zone".to_string())
            })?;

        // Log zone deletion (structured logging)
        log_info!(
            "event=zone_delete zone={} zone_id={}",
            zone_name_clone,
            zone_id
        );

        Ok(())
    }
}
