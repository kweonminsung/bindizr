use crate::{
    api::{
        dto::{CreateZoneDnsConfigRequest, UpdateZoneDnsConfigRequest},
        error::ApiError,
    },
    database::{
        error::DatabaseError, get_dns_instance_repository, get_dns_key_repository,
        get_zone_dns_config_repository, get_zone_history_repository, get_zone_repository,
        model::{zone_dns_config::ZoneDnsConfig, zone_history::ZoneHistory},
    },
    log_error,
};
use chrono::Utc;

#[derive(Clone)]
pub struct ZoneDnsConfigService;

impl ZoneDnsConfigService {
    pub async fn get_zone_dns_configs(zone_id: i32) -> Result<Vec<ZoneDnsConfig>, ApiError> {
        let zone_repository = get_zone_repository();
        let zone_dns_config_repository = get_zone_dns_config_repository();

        // Check if zone exists
        match zone_repository.get_by_id(zone_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "Zone with id {} not found",
                    zone_id
                )))
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch zone".to_string(),
                ));
            }
        }

        zone_dns_config_repository
            .get_by_zone_id(zone_id)
            .await
            .map_err(|e: DatabaseError| {
                log_error!("Failed to fetch zone DNS configurations: {}", e);
                ApiError::InternalServerError(
                    "Failed to fetch zone DNS configurations".to_string(),
                )
            })
    }

    pub async fn create_zone_dns_config(
        zone_id: i32,
        request: &CreateZoneDnsConfigRequest,
    ) -> Result<ZoneDnsConfig, ApiError> {
        let zone_repository = get_zone_repository();
        let dns_instance_repository = get_dns_instance_repository();
        let dns_key_repository = get_dns_key_repository();
        let zone_dns_config_repository = get_zone_dns_config_repository();

        // Check if zone exists
        match zone_repository.get_by_id(zone_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "Zone with id {} not found",
                    zone_id
                )))
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch zone".to_string(),
                ));
            }
        }

        // Validate DNS instance exists
        match dns_instance_repository
            .get_by_id(request.dns_instance_id)
            .await
        {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(ApiError::BadRequest(format!(
                    "DNS instance with id {} not found",
                    request.dns_instance_id
                )))
            }
            Err(e) => {
                log_error!("Failed to validate DNS instance: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to validate DNS instance".to_string(),
                ));
            }
        }

        // Validate DNS key exists
        match dns_key_repository.get_by_id(request.dns_key_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(ApiError::BadRequest(format!(
                    "DNS key with id {} not found",
                    request.dns_key_id
                )))
            }
            Err(e) => {
                log_error!("Failed to validate DNS key: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to validate DNS key".to_string(),
                ));
            }
        }

        let zone_dns_config = ZoneDnsConfig {
            id: 0,
            zone_id,
            dns_instance_id: request.dns_instance_id,
            dns_key_id: request.dns_key_id,
            created_at: Utc::now(),
        };

        let created_config = zone_dns_config_repository
            .create(zone_dns_config)
            .await
            .map_err(|e| {
                log_error!("Failed to create zone DNS configuration: {}", e);
                ApiError::InternalServerError(
                    "Failed to create zone DNS configuration".to_string(),
                )
            })?;

        // Create zone history
        let zone_history_repository = get_zone_history_repository();
        zone_history_repository
            .create(ZoneHistory {
                id: 0,
                log: format!(
                    "[{}] Zone DNS configuration created: id={}, dns_instance_id={}, dns_key_id={}",
                    Utc::now().format("%Y-%m-%d %H:%M:%S"),
                    created_config.id,
                    created_config.dns_instance_id,
                    created_config.dns_key_id,
                ),
                zone_id,
                created_at: Utc::now(),
            })
            .await
            .map_err(|e: DatabaseError| {
                log_error!("Failed to create zone history: {}", e);
                ApiError::InternalServerError("Failed to create zone history".to_string())
            })?;

        Ok(created_config)
    }

    pub async fn update_zone_dns_config(
        zone_id: i32,
        dns_id: i32,
        request: &UpdateZoneDnsConfigRequest,
    ) -> Result<ZoneDnsConfig, ApiError> {
        let zone_repository = get_zone_repository();
        let dns_instance_repository = get_dns_instance_repository();
        let dns_key_repository = get_dns_key_repository();
        let zone_dns_config_repository = get_zone_dns_config_repository();

        // Check if zone exists
        match zone_repository.get_by_id(zone_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "Zone with id {} not found",
                    zone_id
                )))
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch zone".to_string(),
                ));
            }
        }

        // Check if zone DNS config exists
        let mut zone_dns_config = match zone_dns_config_repository.get_by_id(dns_id).await {
            Ok(Some(config)) => {
                if config.zone_id != zone_id {
                    return Err(ApiError::BadRequest(
                        "Zone DNS configuration does not belong to the specified zone"
                            .to_string(),
                    ));
                }
                config
            }
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "Zone DNS configuration with id {} not found",
                    dns_id
                )))
            }
            Err(e) => {
                log_error!("Failed to fetch zone DNS configuration: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch zone DNS configuration".to_string(),
                ));
            }
        };

        // Validate DNS instance exists
        match dns_instance_repository
            .get_by_id(request.dns_instance_id)
            .await
        {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(ApiError::BadRequest(format!(
                    "DNS instance with id {} not found",
                    request.dns_instance_id
                )))
            }
            Err(e) => {
                log_error!("Failed to validate DNS instance: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to validate DNS instance".to_string(),
                ));
            }
        }

        // Validate DNS key exists
        match dns_key_repository.get_by_id(request.dns_key_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(ApiError::BadRequest(format!(
                    "DNS key with id {} not found",
                    request.dns_key_id
                )))
            }
            Err(e) => {
                log_error!("Failed to validate DNS key: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to validate DNS key".to_string(),
                ));
            }
        }

        zone_dns_config.dns_instance_id = request.dns_instance_id;
        zone_dns_config.dns_key_id = request.dns_key_id;

        let updated_config = zone_dns_config_repository
            .update(zone_dns_config)
            .await
            .map_err(|e| {
                log_error!("Failed to update zone DNS configuration: {}", e);
                ApiError::InternalServerError(
                    "Failed to update zone DNS configuration".to_string(),
                )
            })?;

        // Create zone history
        let zone_history_repository = get_zone_history_repository();
        zone_history_repository
            .create(ZoneHistory {
                id: 0,
                log: format!(
                    "[{}] Zone DNS configuration updated: id={}, dns_instance_id={}, dns_key_id={}",
                    Utc::now().format("%Y-%m-%d %H:%M:%S"),
                    updated_config.id,
                    updated_config.dns_instance_id,
                    updated_config.dns_key_id,
                ),
                zone_id,
                created_at: Utc::now(),
            })
            .await
            .map_err(|e: DatabaseError| {
                log_error!("Failed to create zone history: {}", e);
                ApiError::InternalServerError("Failed to create zone history".to_string())
            })?;

        Ok(updated_config)
    }

    pub async fn delete_zone_dns_config(zone_id: i32, dns_id: i32) -> Result<(), ApiError> {
        let zone_repository = get_zone_repository();
        let zone_dns_config_repository = get_zone_dns_config_repository();

        // Check if zone exists
        match zone_repository.get_by_id(zone_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "Zone with id {} not found",
                    zone_id
                )))
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch zone".to_string(),
                ));
            }
        }

        // Check if zone DNS config exists and belongs to the zone
        match zone_dns_config_repository.get_by_id(dns_id).await {
            Ok(Some(config)) => {
                if config.zone_id != zone_id {
                    return Err(ApiError::BadRequest(
                        "Zone DNS configuration does not belong to the specified zone"
                            .to_string(),
                    ));
                }
            }
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "Zone DNS configuration with id {} not found",
                    dns_id
                )))
            }
            Err(e) => {
                log_error!("Failed to fetch zone DNS configuration: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch zone DNS configuration".to_string(),
                ));
            }
        }

        zone_dns_config_repository
            .delete(dns_id)
            .await
            .map_err(|e| {
                log_error!("Failed to delete zone DNS configuration: {}", e);
                ApiError::InternalServerError(
                    "Failed to delete zone DNS configuration".to_string(),
                )
            })
    }
}
