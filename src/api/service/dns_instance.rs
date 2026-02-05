use crate::{
    api::{
        dto::{CreateDnsInstanceRequest, UpdateDnsInstanceRequest},
        error::ApiError,
    },
    database::{
        error::DatabaseError, get_dns_instance_repository, get_dns_key_repository,
        get_zone_dns_config_repository, model::dns_instance::DnsInstance,
    },
    log_error,
};
use chrono::Utc;

#[derive(Clone)]
pub struct DnsInstanceService;

impl DnsInstanceService {
    pub async fn get_dns_instances() -> Result<Vec<DnsInstance>, ApiError> {
        let dns_instance_repository = get_dns_instance_repository();

        dns_instance_repository
            .get_all()
            .await
            .map_err(|e: DatabaseError| {
                log_error!("Failed to fetch DNS instances: {}", e);
                ApiError::InternalServerError("Failed to fetch DNS instances".to_string())
            })
    }

    pub async fn get_dns_instance(id: i32) -> Result<DnsInstance, ApiError> {
        let dns_instance_repository = get_dns_instance_repository();

        match dns_instance_repository.get_by_id(id).await {
            Ok(Some(dns_instance)) => Ok(dns_instance),
            Ok(None) => Err(ApiError::NotFound(format!(
                "DNS instance with id {} not found",
                id
            ))),
            Err(e) => {
                log_error!("Failed to fetch DNS instance: {}", e);
                Err(ApiError::InternalServerError(
                    "Failed to fetch DNS instance".to_string(),
                ))
            }
        }
    }

    pub async fn create_dns_instance(
        request: &CreateDnsInstanceRequest,
    ) -> Result<DnsInstance, ApiError> {
        let dns_instance_repository = get_dns_instance_repository();
        let dns_key_repository = get_dns_key_repository();

        // Check if dns_key exists
        match dns_key_repository.get_by_id(request.rndc_key_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(ApiError::BadRequest(format!(
                    "DNS key with id {} not found",
                    request.rndc_key_id
                )));
            }
            Err(e) => {
                log_error!("Failed to validate DNS key: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to validate DNS key".to_string(),
                ));
            }
        }

        let dns_instance = DnsInstance {
            id: 0,
            name: request.name.clone(),
            host: request.host.clone(),
            rndc_port: request.rndc_port,
            rndc_key_id: request.rndc_key_id,
            created_at: Utc::now(),
        };

        dns_instance_repository
            .create(dns_instance)
            .await
            .map_err(|e| {
                log_error!("Failed to create DNS instance: {}", e);
                ApiError::InternalServerError("Failed to create DNS instance".to_string())
            })
    }

    pub async fn update_dns_instance(
        id: i32,
        request: &UpdateDnsInstanceRequest,
    ) -> Result<DnsInstance, ApiError> {
        let dns_instance_repository = get_dns_instance_repository();
        let dns_key_repository = get_dns_key_repository();

        // Check if DNS instance exists
        let mut dns_instance = match dns_instance_repository.get_by_id(id).await {
            Ok(Some(dns_instance)) => dns_instance,
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "DNS instance with id {} not found",
                    id
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch DNS instance: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch DNS instance".to_string(),
                ));
            }
        };

        // Check if dns_key exists
        match dns_key_repository.get_by_id(request.rndc_key_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(ApiError::BadRequest(format!(
                    "DNS key with id {} not found",
                    request.rndc_key_id
                )));
            }
            Err(e) => {
                log_error!("Failed to validate DNS key: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to validate DNS key".to_string(),
                ));
            }
        }

        dns_instance.name = request.name.clone();
        dns_instance.host = request.host.clone();
        dns_instance.rndc_port = request.rndc_port;
        dns_instance.rndc_key_id = request.rndc_key_id;

        dns_instance_repository
            .update(dns_instance)
            .await
            .map_err(|e| {
                log_error!("Failed to update DNS instance: {}", e);
                ApiError::InternalServerError("Failed to update DNS instance".to_string())
            })
    }

    pub async fn delete_dns_instance(id: i32) -> Result<(), ApiError> {
        let dns_instance_repository = get_dns_instance_repository();
        let zone_dns_config_repository = get_zone_dns_config_repository();

        // Check if DNS instance exists
        match dns_instance_repository.get_by_id(id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "DNS instance with id {} not found",
                    id
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch DNS instance: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch DNS instance".to_string(),
                ));
            }
        }

        // Check if DNS instance is used in zone configurations
        match zone_dns_config_repository.get_by_dns_instance_id(id).await {
            Ok(configs) => {
                if !configs.is_empty() {
                    return Err(ApiError::BadRequest(
                        "Cannot delete DNS instance that is used in zone configurations"
                            .to_string(),
                    ));
                }
            }
            Err(e) => {
                log_error!("Failed to check zone configurations: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to check zone configurations".to_string(),
                ));
            }
        }

        dns_instance_repository.delete(id).await.map_err(|e| {
            log_error!("Failed to delete DNS instance: {}", e);
            ApiError::InternalServerError("Failed to delete DNS instance".to_string())
        })
    }

    pub async fn get_dns_instance_keys(
        id: i32,
    ) -> Result<Vec<crate::database::model::dns_key::DnsKey>, ApiError> {
        let dns_instance_repository = get_dns_instance_repository();
        let dns_key_repository = get_dns_key_repository();

        // Check if DNS instance exists
        match dns_instance_repository.get_by_id(id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "DNS instance with id {} not found",
                    id
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch DNS instance: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch DNS instance".to_string(),
                ));
            }
        }

        // Get all DNS keys (dns_instance_id field removed)
        match dns_key_repository.get_all().await {
            Ok(keys) => Ok(keys),
            Err(e) => {
                log_error!("Failed to fetch DNS keys: {}", e);
                Err(ApiError::InternalServerError(
                    "Failed to fetch DNS keys".to_string(),
                ))
            }
        }
    }

    pub async fn get_dns_instance_zones(id: i32) -> Result<Vec<i32>, ApiError> {
        let dns_instance_repository = get_dns_instance_repository();
        let zone_dns_config_repository = get_zone_dns_config_repository();

        // Check if DNS instance exists
        match dns_instance_repository.get_by_id(id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(ApiError::NotFound(format!(
                    "DNS instance with id {} not found",
                    id
                )));
            }
            Err(e) => {
                log_error!("Failed to fetch DNS instance: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to fetch DNS instance".to_string(),
                ));
            }
        }

        match zone_dns_config_repository.get_by_dns_instance_id(id).await {
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
