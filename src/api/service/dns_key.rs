use crate::{
    api::{
        dto::{CreateDnsKeyRequest, UpdateDnsKeyRequest},
        error::ApiError,
    },
    database::{
        error::DatabaseError, get_dns_key_repository, get_dns_repository, get_key_repository,
        get_zone_dns_config_repository, model::dns_key::DnsKey,
    },
    log_error,
};
use chrono::Utc;

#[derive(Clone)]
pub struct DnsKeyService;

impl DnsKeyService {
    pub async fn get_dns_keys(name: &str) -> Result<Vec<(DnsKey, String)>, ApiError> {
        let dns_repository = get_dns_repository();
        let dns_key_repository = get_dns_key_repository();
        let key_repository = get_key_repository();

        // Check if DNS exists and get its ID
        let dns = match dns_repository.get_by_name(name).await {
            Ok(Some(d)) => d,
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "DNS with name '{}' not found",
                    name
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch DNS: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch DNS".to_string(),
                ));
            }
        };

        // Get the DNS keys associated with this DNS
        let dns_keys = dns_key_repository
            .get_by_dns_id(dns.id)
            .await
            .map_err(|e| {
                log_error!("Failed to fetch DNS keys: {}", e);
                ApiError::InternalServerError("Failed to fetch DNS keys".to_string())
            })?;

        // Fetch key names for each dns_key
        let mut result = Vec::new();
        for dns_key in dns_keys {
            let key_name = match key_repository.get_by_id(dns_key.key_id).await {
                Ok(Some(k)) => k.name,
                Ok(None) => Err(ApiError::InternalServerError(
                    "Associated key not found".to_string(),
                ))?,
                Err(e) => {
                    log_error!("Failed to fetch Key: {}", e);
                    return Err(ApiError::InternalServerError(
                        "Failed to fetch Key".to_string(),
                    ));
                }
            };
            result.push((dns_key, key_name));
        }

        Ok(result)
    }

    pub async fn create_dns_key(
        request: &CreateDnsKeyRequest,
    ) -> Result<(DnsKey, String, String), ApiError> {
        let dns_repository = get_dns_repository();
        let key_repository = get_key_repository();
        let dns_key_repository = get_dns_key_repository();

        // Check if DNS exists and get dns_id
        let dns = match dns_repository.get_by_name(&request.dns_name).await {
            Ok(Some(d)) => d,
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "DNS with name '{}' not found",
                    request.dns_name
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch DNS: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch DNS".to_string(),
                ));
            }
        };

        // Check if Key exists and get key_id
        let key = match key_repository.get_by_name(&request.key_name).await {
            Ok(Some(k)) => k,
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "Key with name '{}' not found",
                    request.key_name
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch Key: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch Key".to_string(),
                ));
            }
        };

        // Check if dns_key already exists for this DNS
        let existing_keys =
            dns_key_repository
                .get_by_dns_id(dns.id)
                .await
                .map_err(|e: DatabaseError| {
                    log_error!("Failed to check existing dns_key: {}", e);
                    ApiError::InternalServerError("Failed to check existing dns_key".to_string())
                })?;

        if !existing_keys.is_empty() {
            return Err(ApiError::BadRequest(format!(
                "DNS '{}' already has a key configured",
                request.dns_name
            )));
        }

        let dns_key = DnsKey {
            id: 0,
            dns_id: dns.id,
            key_id: key.id,
            created_at: Utc::now(),
        };

        let created = dns_key_repository
            .create(dns_key)
            .await
            .map_err(|e: DatabaseError| {
                log_error!("Failed to create DNS key: {}", e);
                ApiError::InternalServerError("Failed to create DNS key".to_string())
            })?;

        Ok((created, dns.name, key.name))
    }

    pub async fn update_dns_key(
        dns_name: &str,
        request: &UpdateDnsKeyRequest,
    ) -> Result<(DnsKey, String, String), ApiError> {
        let dns_repository = get_dns_repository();
        let key_repository = get_key_repository();
        let dns_key_repository = get_dns_key_repository();

        // Check if DNS exists and get dns_id
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

        // Get existing dns_key
        let dns_keys =
            dns_key_repository
                .get_by_dns_id(dns.id)
                .await
                .map_err(|e: DatabaseError| {
                    log_error!("Failed to fetch DNS key: {}", e);
                    ApiError::InternalServerError("Failed to fetch DNS key".to_string())
                })?;

        let mut dns_key = dns_keys.into_iter().next().ok_or_else(|| {
            ApiError::NotFound(format!("DNS key for DNS '{}' not found", dns_name))
        })?;

        // Check if new key exists and get key_id
        let key = match key_repository.get_by_name(&request.key_name).await {
            Ok(Some(k)) => k,
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "Key with name '{}' not found",
                    request.key_name
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch Key: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch Key".to_string(),
                ));
            }
        };

        dns_key.key_id = key.id;

        let updated = dns_key_repository
            .update(dns_key)
            .await
            .map_err(|e: DatabaseError| {
                log_error!("Failed to update DNS key: {}", e);
                ApiError::InternalServerError("Failed to update DNS key".to_string())
            })?;

        Ok((updated, dns.name, key.name))
    }

    pub async fn delete_dns_key(dns_name: &str) -> Result<(), ApiError> {
        let dns_repository = get_dns_repository();
        let dns_key_repository = get_dns_key_repository();

        // Check if DNS exists and get dns_id
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

        // Get existing dns_key
        let dns_keys =
            dns_key_repository
                .get_by_dns_id(dns.id)
                .await
                .map_err(|e: DatabaseError| {
                    log_error!("Failed to fetch DNS key: {}", e);
                    ApiError::InternalServerError("Failed to fetch DNS key".to_string())
                })?;

        let dns_key = dns_keys.into_iter().next().ok_or_else(|| {
            ApiError::NotFound(format!("DNS key for DNS '{}' not found", dns_name))
        })?;

        dns_key_repository
            .delete(dns_key.id)
            .await
            .map_err(|e: DatabaseError| {
                log_error!("Failed to delete DNS key: {}", e);
                ApiError::InternalServerError("Failed to delete DNS key".to_string())
            })
    }

    pub async fn get_dns_zones(name: &str) -> Result<Vec<i32>, ApiError> {
        let dns_repository = get_dns_repository();
        let zone_dns_config_repository = get_zone_dns_config_repository();

        // Check if DNS exists and get its ID
        let dns_id = match dns_repository.get_by_name(name).await {
            Ok(Some(dns)) => dns.id,
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "DNS with name '{}' not found",
                    name
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch DNS: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch DNS".to_string(),
                ));
            }
        };

        match zone_dns_config_repository.get_by_dns_id(dns_id).await {
            Ok(configs) => Ok(configs.into_iter().map(|c| c.zone_id).collect()),
            Err(e) => {
                log_error!("Failed to fetch zone configurations: {}", e);
                Err(ApiError::InternalServerError(
                    "Failed to fetch zone configurations".to_string(),
                ))
            }
        }
    }
}
