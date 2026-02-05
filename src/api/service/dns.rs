use crate::{
    api::{
        dto::{CreateDnsRequest, UpdateDnsRequest},
        error::ApiError,
    },
    database::{
        error::DatabaseError, get_dns_repository, get_zone_dns_config_repository, model::dns::Dns,
    },
    log_error,
};
use chrono::Utc;

#[derive(Clone)]
pub struct DnsService;

impl DnsService {
    pub async fn get_dnss() -> Result<Vec<Dns>, ApiError> {
        let dns_repository = get_dns_repository();

        dns_repository.get_all().await.map_err(|e: DatabaseError| {
            log_error!("Failed to fetch DNS servers: {}", e);
            ApiError::InternalServerError("Failed to fetch DNS servers".to_string())
        })
    }

    pub async fn get_dns(name: &str) -> Result<Dns, ApiError> {
        let dns_repository = get_dns_repository();

        match dns_repository.get_by_name(name).await {
            Ok(Some(dns)) => Ok(dns),
            Ok(None) => Err(ApiError::NotFound(format!(
                "DNS with name '{}' not found",
                name
            ))),
            Err(e) => {
                log_error!("Failed to fetch DNS: {}", e);
                Err(ApiError::InternalServerError(
                    "Failed to fetch DNS".to_string(),
                ))
            }
        }
    }

    pub async fn create_dns(request: &CreateDnsRequest) -> Result<Dns, ApiError> {
        let dns_repository = get_dns_repository();

        // Check if name already exists
        match dns_repository.get_by_name(&request.name).await {
            Ok(Some(_)) => {
                return Err(ApiError::BadRequest(format!(
                    "DNS with name '{}' already exists",
                    request.name
                )));
            }
            Ok(None) => {}
            Err(e) => {
                log_error!("Failed to check DNS name: {}", e);
                return Err(ApiError::InternalServerError(
                    "Failed to check DNS name".to_string(),
                ));
            }
        }

        let dns = Dns {
            id: 0,
            name: request.name.clone(),
            host: request.host.clone(),
            rndc_port: request.rndc_port,
            created_at: Utc::now(),
        };

        dns_repository.create(dns).await.map_err(|e| {
            log_error!("Failed to create DNS: {}", e);
            ApiError::InternalServerError("Failed to create DNS".to_string())
        })
    }

    pub async fn update_dns(name: &str, request: &UpdateDnsRequest) -> Result<Dns, ApiError> {
        let dns_repository = get_dns_repository();

        // Check if DNS exists
        let mut dns = match dns_repository.get_by_name(name).await {
            Ok(Some(dns)) => dns,
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

        // If name is being changed, check if new name already exists
        if request.name != dns.name {
            match dns_repository.get_by_name(&request.name).await {
                Ok(Some(_)) => {
                    return Err(ApiError::BadRequest(format!(
                        "DNS with name '{}' already exists",
                        request.name
                    )));
                }
                Ok(None) => {}
                Err(e) => {
                    log_error!("Failed to check DNS name: {}", e);
                    return Err(ApiError::InternalServerError(
                        "Failed to check DNS name".to_string(),
                    ));
                }
            }
        }

        dns.name = request.name.clone();
        dns.host = request.host.clone();
        dns.rndc_port = request.rndc_port;

        dns_repository.update(dns).await.map_err(|e| {
            log_error!("Failed to update DNS: {}", e);
            ApiError::InternalServerError("Failed to update DNS".to_string())
        })
    }

    pub async fn delete_dns(name: &str) -> Result<(), ApiError> {
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

        // Check if DNS is used in zone configurations
        match zone_dns_config_repository.get_by_dns_id(dns_id).await {
            Ok(configs) => {
                if !configs.is_empty() {
                    return Err(ApiError::BadRequest(
                        "Cannot delete DNS that is used in zone configurations".to_string(),
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

        // dns_keys will be automatically deleted due to ON DELETE CASCADE

        dns_repository.delete(dns_id).await.map_err(|e| {
            log_error!("Failed to delete DNS: {}", e);
            ApiError::InternalServerError("Failed to delete DNS".to_string())
        })
    }
}
