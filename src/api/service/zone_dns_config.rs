use crate::{
    api::{
        dto::{CreateZoneDnsConfigRequest, UpdateZoneDnsConfigRequest},
        error::ApiError,
    },
    database::{
        error::DatabaseError,
        get_dns_repository, get_key_repository, get_zone_dns_config_repository,
        get_zone_history_repository, get_zone_repository,
        model::{zone_dns_config::ZoneDnsConfig, zone_history::ZoneHistory},
    },
    log_error,
};
use chrono::Utc;

#[derive(Clone)]
pub struct ZoneDnsConfigService;

impl ZoneDnsConfigService {
    pub async fn get_zone_dns_configs(zone_name: &str) -> Result<Vec<ZoneDnsConfig>, ApiError> {
        let zone_repository = get_zone_repository();
        let zone_dns_config_repository = get_zone_dns_config_repository();

        // Check if zone exists and get zone_id
        let zone = match zone_repository.get_by_name(zone_name).await {
            Ok(Some(z)) => z,
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "Zone with name '{}' not found",
                    zone_name
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch zone".to_string(),
                ));
            }
        };

        zone_dns_config_repository
            .get_by_zone_id(zone.id)
            .await
            .map_err(|e: DatabaseError| {
                log_error!("Failed to fetch zone DNS configurations: {}", e);
                ApiError::InternalServerError("Failed to fetch zone DNS configurations".to_string())
            })
    }

    pub async fn create_zone_dns_config(
        zone_name: &str,
        request: &CreateZoneDnsConfigRequest,
    ) -> Result<ZoneDnsConfig, ApiError> {
        let zone_repository = get_zone_repository();
        let dns_repository = get_dns_repository();
        let key_repository = get_key_repository();
        let zone_dns_config_repository = get_zone_dns_config_repository();

        // Check if zone exists and get zone_id
        let zone = match zone_repository.get_by_name(zone_name).await {
            Ok(Some(z)) => z,
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "Zone with name '{}' not found",
                    zone_name
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch zone".to_string(),
                ));
            }
        };

        // Validate DNS exists and get dns_id
        let dns = match dns_repository.get_by_name(&request.dns_name).await {
            Ok(Some(d)) => d,
            Ok(None) => {
                return Err(ApiError::BadRequest(format!(
                    "DNS with name '{}' not found",
                    request.dns_name
                )));
            }
            Err(e) => {
                log_error!("Failed to validate DNS: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to validate DNS".to_string(),
                ));
            }
        };

        // Validate key exists
        let key = match key_repository.get_by_id(request.key_id).await {
            Ok(Some(k)) => k,
            Ok(None) => {
                return Err(ApiError::BadRequest(format!(
                    "Key with id {} not found",
                    request.key_id
                )));
            }
            Err(e) => {
                log_error!("Failed to validate Key: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to validate Key".to_string(),
                ));
            }
        };

        let zone_dns_config = ZoneDnsConfig {
            id: 0,
            zone_id: zone.id,
            dns_id: dns.id,
            key_id: request.key_id,
            created_at: Utc::now(),
        };

        let created_config = zone_dns_config_repository
            .create(zone_dns_config)
            .await
            .map_err(|e| {
                log_error!("Failed to create zone DNS configuration: {}", e);
                ApiError::InternalServerError("Failed to create zone DNS configuration".to_string())
            })?;

        // Create zone history
        let zone_history_repository = get_zone_history_repository();
        zone_history_repository
            .create(ZoneHistory {
                id: 0,
                log: format!(
                    "[{}] Zone DNS configuration created: dns_name={}, key_name={}",
                    Utc::now().format("%Y-%m-%d %H:%M:%S"),
                    dns.name,
                    key.name,
                ),
                zone_name: zone.name.clone(),
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
        zone_name: &str,
        current_dns_name: &str,
        request: &UpdateZoneDnsConfigRequest,
    ) -> Result<ZoneDnsConfig, ApiError> {
        let zone_repository = get_zone_repository();
        let dns_repository = get_dns_repository();
        let key_repository = get_key_repository();
        let zone_dns_config_repository = get_zone_dns_config_repository();

        // Check if zone exists and get zone_id
        let zone = match zone_repository.get_by_name(zone_name).await {
            Ok(Some(z)) => z,
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "Zone with name '{}' not found",
                    zone_name
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch zone".to_string(),
                ));
            }
        };

        // Get current DNS instance by name
        let current_dns = match dns_repository.get_by_name(current_dns_name).await {
            Ok(Some(d)) => d,
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "DNS with name '{}' not found",
                    current_dns_name
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch DNS: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch DNS".to_string(),
                ));
            }
        };

        // Get current key by id
        let current_key = match key_repository.get_by_id(request.key_id).await {
            Ok(Some(k)) => k,
            Ok(None) => {
                return Err(ApiError::BadRequest(format!(
                    "Key with id {} not found",
                    request.key_id
                )));
            }
            Err(e) => {
                log_error!("Failed to validate Key: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to validate Key".to_string(),
                ));
            }
        };

        // Find zone DNS config by zone_id and current dns_id
        let configs = zone_dns_config_repository
            .get_by_zone_id(zone.id)
            .await
            .map_err(|e| {
                log_error!("Failed to fetch zone DNS configurations: {}", e);
                ApiError::InternalServerError("Failed to fetch zone DNS configurations".to_string())
            })?;

        let mut zone_dns_config = configs
            .into_iter()
            .find(|c| c.dns_id == current_dns.id)
            .ok_or_else(|| {
                ApiError::NotFound(format!(
                    "Zone DNS configuration for zone '{}' and DNS '{}' not found",
                    zone_name, current_dns_name
                ))
            })?;

        // Validate new DNS exists and get new dns_id
        let new_dns = match dns_repository.get_by_name(&request.dns_name).await {
            Ok(Some(d)) => d,
            Ok(None) => {
                return Err(ApiError::BadRequest(format!(
                    "DNS with name '{}' not found",
                    request.dns_name
                )));
            }
            Err(e) => {
                log_error!("Failed to validate DNS: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to validate DNS".to_string(),
                ));
            }
        };

        // Validate key exists
        let new_key = match key_repository.get_by_id(request.key_id).await {
            Ok(Some(k)) => k,
            Ok(None) => {
                return Err(ApiError::BadRequest(format!(
                    "Key with id {} not found",
                    request.key_id
                )));
            }
            Err(e) => {
                log_error!("Failed to validate Key: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to validate Key".to_string(),
                ));
            }
        };

        zone_dns_config.dns_id = new_dns.id;
        zone_dns_config.key_id = request.key_id;

        let updated_config = zone_dns_config_repository
            .update(zone_dns_config)
            .await
            .map_err(|e| {
                log_error!("Failed to update zone DNS configuration: {}", e);
                ApiError::InternalServerError("Failed to update zone DNS configuration".to_string())
            })?;

        // Create zone history
        let zone_history_repository = get_zone_history_repository();
        zone_history_repository
            .create(ZoneHistory {
                id: 0,
                log: format!(
                    "[{}] Zone DNS configuration updated: previous_dns_name={}, new_dns_name={}, previous_key_name={}, new_key_name={}",
                    Utc::now().format("%Y-%m-%d %H:%M:%S"),
                    current_dns.name,
                    new_dns.name,
                    current_key.name,
                    new_key.name,
                ),
                zone_name: zone.name.clone(),
                created_at: Utc::now(),
            })
            .await
            .map_err(|e: DatabaseError| {
                log_error!("Failed to create zone history: {}", e);
                ApiError::InternalServerError("Failed to create zone history".to_string())
            })?;

        Ok(updated_config)
    }

    pub async fn delete_zone_dns_config(zone_name: &str, dns_name: &str) -> Result<(), ApiError> {
        let zone_repository = get_zone_repository();
        let dns_repository = get_dns_repository();
        let zone_dns_config_repository = get_zone_dns_config_repository();

        // Check if zone exists and get zone_id
        let zone = match zone_repository.get_by_name(zone_name).await {
            Ok(Some(z)) => z,
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "Zone with name '{}' not found",
                    zone_name
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch zone".to_string(),
                ));
            }
        };

        // Get DNS instance by name
        let dns = match dns_repository.get_by_name(dns_name).await {
            Ok(Some(d)) => d,
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "DNS with name '{}' not found",
                    dns_name
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch DNS: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch DNS".to_string(),
                ));
            }
        };

        // Find zone DNS config by zone_id and dns_id
        let configs = zone_dns_config_repository
            .get_by_zone_id(zone.id)
            .await
            .map_err(|e| {
                log_error!("Failed to fetch zone DNS configurations: {}", e);
                ApiError::InternalServerError("Failed to fetch zone DNS configurations".to_string())
            })?;

        let zone_dns_config = configs
            .into_iter()
            .find(|c| c.dns_id == dns.id)
            .ok_or_else(|| {
                ApiError::NotFound(format!(
                    "Zone DNS configuration for zone '{}' and DNS '{}' not found",
                    zone_name, dns_name
                ))
            })?;

        zone_dns_config_repository
            .delete(zone_dns_config.id)
            .await
            .map_err(|e| {
                log_error!("Failed to delete zone DNS configuration: {}", e);
                ApiError::InternalServerError("Failed to delete zone DNS configuration".to_string())
            })
    }
}
