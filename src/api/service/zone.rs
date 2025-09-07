use crate::{
    api::dto::CreateZoneRequest,
    database::{
        get_zone_history_repository, get_zone_repository,
        model::{zone::Zone, zone_history::ZoneHistory},
    },
    log_error,
};
use chrono::Utc;

#[derive(Clone)]
pub struct ZoneService;

impl ZoneService {
    pub async fn get_zones() -> Result<Vec<Zone>, String> {
        let zone_repository = get_zone_repository();

        match zone_repository.get_all().await {
            Ok(zones) => Ok(zones),
            Err(e) => {
                log_error!("Failed to fetch zones: {}", e);
                Err("Failed to fetch zones".to_string())
            }
        }
    }

    pub async fn get_zone(zone_id: i32) -> Result<Zone, String> {
        let zone_repository = get_zone_repository();

        match zone_repository.get_by_id(zone_id).await {
            Ok(Some(zone)) => Ok(zone),
            Ok(None) => Err(format!("Zone with id {} not found", zone_id)),
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                Err("Failed to fetch zone".to_string())
            }
        }
    }

    pub async fn create_zone(create_zone_request: &CreateZoneRequest) -> Result<Zone, String> {
        let zone_repository = get_zone_repository();
        let zone_history_repository = get_zone_history_repository();

        // Check if zone already exists
        match zone_repository.get_by_name(&create_zone_request.name).await {
            Ok(Some(_)) => {
                log_error!("Zone with name {} already exists", create_zone_request.name);
                return Err("Zone with this name already exists".to_string());
            }
            Ok(None) => (),
            Err(e) => {
                log_error!("Failed to check existing zone: {}", e);
                return Err("Failed to create zone".to_string());
            }
        };

        // Create zone
        let created_zone = zone_repository
            .create(Zone {
                id: 0, // Will be set by the database
                name: create_zone_request.name.clone(),
                primary_ns: create_zone_request.primary_ns.clone(),
                primary_ns_ip: create_zone_request.primary_ns_ip.clone(),
                admin_email: create_zone_request.admin_email.clone(),
                ttl: create_zone_request.ttl,
                serial: create_zone_request.serial,
                refresh: create_zone_request.refresh.unwrap_or(86400),
                retry: create_zone_request.retry.unwrap_or(7200),
                expire: create_zone_request.expire.unwrap_or(3600000),
                minimum_ttl: create_zone_request.minimum_ttl.unwrap_or(86400),
                created_at: Utc::now(), // Will be set by the database
            })
            .await
            .map_err(|e| {
                log_error!("Failed to create zone: {}", e);
                "Failed to create zone".to_string()
            })?;

        // Create zone history
        zone_history_repository
            .create(ZoneHistory {
                id: 0, // Will be set by the database
                log: format!(
                    "[{}] Zone created: id={}, name={}",
                    Utc::now().format("%Y-%m-%d %H:%M:%S"),
                    created_zone.id,
                    created_zone.name,
                ),
                zone_id: created_zone.id,
                created_at: Utc::now(), // Will be set by the database
            })
            .await
            .map_err(|e| {
                log_error!("Failed to create zone history: {}", e);
                "Failed to create zone history".to_string()
            })?;

        Ok(created_zone)
    }

    pub async fn update_zone(
        zone_id: i32,
        update_zone_request: &CreateZoneRequest,
    ) -> Result<Zone, String> {
        let zone_repository = get_zone_repository();
        let zone_history_repository = get_zone_history_repository();

        // Check if zone exists
        match zone_repository.get_by_id(zone_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                log_error!("Zone with id {} not found", zone_id);
                return Err(format!("Zone with id {} not found", zone_id));
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err("Failed to update zone".to_string());
            }
        };

        // Check if zone with the same name already exists
        match zone_repository.get_by_name(&update_zone_request.name).await {
            Ok(Some(existing_zone)) if existing_zone.id != zone_id => {
                log_error!("Zone with name {} already exists", update_zone_request.name);
                return Err("Zone with this name already exists".to_string());
            }
            Ok(Some(_)) => (), // The same zone, allow update
            Ok(None) => (),
            Err(e) => {
                log_error!("Failed to check existing zone: {}", e);
                return Err("Failed to update zone".to_string());
            }
        };

        // Update zone
        let updated_zone = zone_repository
            .update(Zone {
                id: zone_id,
                name: update_zone_request.name.clone(),
                primary_ns: update_zone_request.primary_ns.clone(),
                primary_ns_ip: update_zone_request.primary_ns_ip.clone(),
                admin_email: update_zone_request.admin_email.clone(),
                ttl: update_zone_request.ttl,
                serial: update_zone_request.serial,
                refresh: update_zone_request.refresh.unwrap_or(86400),
                retry: update_zone_request.retry.unwrap_or(7200),
                expire: update_zone_request.expire.unwrap_or(3600000),
                minimum_ttl: update_zone_request.minimum_ttl.unwrap_or(86400),
                created_at: Utc::now(), // Will be set by the database
            })
            .await
            .map_err(|e| {
                log_error!("Failed to update zone: {}", e);
                "Failed to update zone".to_string()
            })?;

        // Create zone history
        zone_history_repository
            .create(ZoneHistory {
                id: 0, // Will be set by the database
                log: format!(
                    "[{}] Zone updated: id={}, name={}",
                    Utc::now().format("%Y-%m-%d %H:%M:%S"),
                    zone_id,
                    update_zone_request.name,
                ),
                zone_id,
                created_at: Utc::now(), // Will be set by the database
            })
            .await
            .map_err(|e| {
                log_error!("Failed to create zone history: {}", e);
                "Failed to create zone history".to_string()
            })?;

        Ok(updated_zone)
    }

    pub async fn delete_zone(zone_id: i32) -> Result<(), String> {
        let zone_repository = get_zone_repository();
        // let zone_history_repository = get_zone_history_repository();

        // Check if zone exists
        match zone_repository.get_by_id(zone_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                log_error!("Zone with id {} not found", zone_id);
                return Err(format!("Zone with id {} not found", zone_id));
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err("Failed to update zone".to_string());
            }
        };

        // Delete zone
        zone_repository.delete(zone_id).await.map_err(|e| {
            log_error!("Failed to delete zone: {}", e);
            "Failed to delete zone".to_string()
        })?;

        // Create zone history
        // zone_history_repository
        //     .create(ZoneHistory {
        //         id: 0, // Will be set by the database
        //         log: format!(
        //             "[{}] Zone deleted: id={}",
        //             Utc::now().format("%Y-%m-%d %H:%M:%S"),
        //             zone_id,
        //         ),
        //         zone_id,
        //         created_at: Utc::now(), // Will be set by the database
        //     })
        //     .await
        //     .map_err(|e| {
        //         log_error!("Failed to create zone history: {}", e);
        //         "Failed to create zone history".to_string()
        //     })?;

        Ok(())
    }
}
