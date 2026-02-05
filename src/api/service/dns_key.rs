use crate::{
    api::error::ApiError,
    database::{get_dns_key_repository, get_dns_repository, get_zone_dns_config_repository},
    log_error,
};

#[derive(Clone)]
pub struct DnsKeyService;

impl DnsKeyService {
    pub async fn get_dns_keys(
        name: &str,
    ) -> Result<Vec<crate::database::model::dns_key::DnsKey>, ApiError> {
        let dns_repository = get_dns_repository();
        let dns_key_repository = get_dns_key_repository();

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

        // Get the DNS keys associated with this DNS
        match dns_key_repository.get_by_dns_id(dns_id).await {
            Ok(dns_keys) => Ok(dns_keys),
            Err(e) => {
                log_error!("Failed to fetch DNS keys: {}", e);
                Err(ApiError::InternalServerError(
                    "Failed to fetch DNS keys".to_string(),
                ))
            }
        }
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
