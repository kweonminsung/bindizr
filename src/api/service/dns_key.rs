use crate::{
    api::{
        dto::{CreateDnsKeyRequest, UpdateDnsKeyRequest},
        error::ApiError,
    },
    database::{
        error::DatabaseError,
        get_dns_instance_repository, get_dns_key_repository,
        model::dns_key::{DnsKey, DnsKeyAlgorithm, DnsKeyType},
    },
    log_error,
};
use chrono::Utc;

#[derive(Clone)]
pub struct DnsKeyService;

impl DnsKeyService {
    pub async fn get_dns_keys() -> Result<Vec<DnsKey>, ApiError> {
        let dns_key_repository = get_dns_key_repository();

        dns_key_repository
            .get_all()
            .await
            .map_err(|e: DatabaseError| {
                log_error!("Failed to fetch DNS keys: {}", e);
                ApiError::InternalServerError("Failed to fetch DNS keys".to_string())
            })
    }

    pub async fn get_dns_key(id: i32) -> Result<DnsKey, ApiError> {
        let dns_key_repository = get_dns_key_repository();

        match dns_key_repository.get_by_id(id).await {
            Ok(Some(dns_key)) => Ok(dns_key),
            Ok(None) => Err(ApiError::NotFound(format!(
                "DNS key with id {} not found",
                id
            ))),
            Err(e) => {
                log_error!("Failed to fetch DNS key: {}", e);
                Err(ApiError::InternalServerError(
                    "Failed to fetch DNS key".to_string(),
                ))
            }
        }
    }

    pub async fn create_dns_key(request: &CreateDnsKeyRequest) -> Result<DnsKey, ApiError> {
        let dns_key_repository = get_dns_key_repository();

        // Parse key type
        let key_type = DnsKeyType::from_str(&request.key_type)
            .map_err(|e| ApiError::BadRequest(format!("Invalid key type: {}", e)))?;

        // Parse key algorithm
        let key_algorithm = DnsKeyAlgorithm::from_str(&request.key_algorithm)
            .map_err(|e| ApiError::BadRequest(format!("Invalid key algorithm: {}", e)))?;

        let dns_key = DnsKey {
            id: 0,
            name: request.name.clone(),
            key_type,
            key_algorithm,
            key_name: request.key_name.clone(),
            secret: request.secret.clone(),
            created_at: Utc::now(),
        };

        dns_key_repository.create(dns_key).await.map_err(|e| {
            log_error!("Failed to create DNS key: {}", e);
            ApiError::InternalServerError("Failed to create DNS key".to_string())
        })
    }

    pub async fn update_dns_key(
        id: i32,
        request: &UpdateDnsKeyRequest,
    ) -> Result<DnsKey, ApiError> {
        let dns_key_repository = get_dns_key_repository();

        // Check if DNS key exists
        let mut dns_key = match dns_key_repository.get_by_id(id).await {
            Ok(Some(dns_key)) => dns_key,
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "DNS key with id {} not found",
                    id
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch DNS key: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch DNS key".to_string(),
                ));
            }
        };

        // Parse key type
        let key_type = DnsKeyType::from_str(&request.key_type)
            .map_err(|e| ApiError::BadRequest(format!("Invalid key type: {}", e)))?;

        // Parse key algorithm
        let key_algorithm = DnsKeyAlgorithm::from_str(&request.key_algorithm)
            .map_err(|e| ApiError::BadRequest(format!("Invalid key algorithm: {}", e)))?;

        dns_key.name = request.name.clone();
        dns_key.key_type = key_type;
        dns_key.key_algorithm = key_algorithm;
        dns_key.key_name = request.key_name.clone();
        dns_key.secret = request.secret.clone();

        dns_key_repository.update(dns_key).await.map_err(|e| {
            log_error!("Failed to update DNS key: {}", e);
            ApiError::InternalServerError("Failed to update DNS key".to_string())
        })
    }

    pub async fn delete_dns_key(id: i32) -> Result<(), ApiError> {
        let dns_key_repository = get_dns_key_repository();
        let dns_instance_repository = get_dns_instance_repository();

        // Check if DNS key exists
        match dns_key_repository.get_by_id(id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "DNS key with id {} not found",
                    id
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch DNS key: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch DNS key".to_string(),
                ));
            }
        }

        // Check if DNS key is used as rndc_key in any DNS instance
        match dns_instance_repository.get_all().await {
            Ok(instances) => {
                let is_used = instances.iter().any(|i| i.rndc_key_id == id);
                if is_used {
                    return Err(ApiError::BadRequest(
                        "Cannot delete DNS key that is used as RNDC key in DNS instances"
                            .to_string(),
                    ));
                }
            }
            Err(e) => {
                log_error!("Failed to check DNS instances: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to check DNS instances".to_string(),
                ));
            }
        }

        dns_key_repository.delete(id).await.map_err(|e| {
            log_error!("Failed to delete DNS key: {}", e);
            ApiError::InternalServerError("Failed to delete DNS key".to_string())
        })
    }
}
