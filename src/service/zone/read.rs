use crate::{
    database::model::zone::Zone,
    log_error,
    service::{error::ServiceError, repository::RepositoryService},
};

use super::ZoneService;

impl ZoneService {
    pub async fn get_zones() -> Result<Vec<Zone>, ServiceError> {
        RepositoryService::get_all_zones().await.map_err(|e| {
            log_error!("Failed to fetch zones: {}", e);
            ServiceError::Internal("Failed to fetch zones".to_string())
        })
    }

    pub async fn get_zone(zone_name: &str) -> Result<Zone, ServiceError> {
        match RepositoryService::get_zone_by_name(zone_name).await {
            Ok(Some(zone)) => Ok(zone),
            Ok(None) => Err(ServiceError::NotFound(format!(
                "Zone with name '{}' not found",
                zone_name
            ))),
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                Err(ServiceError::Internal("Failed to fetch zone".to_string()))
            }
        }
    }
}
