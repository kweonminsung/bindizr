use crate::{
    RepositoryTx,
    error::ServiceError,
    log_error,
    model::{zone::Zone, zone_change::ZoneChange},
    repository::RepositoryService,
    types::GetZonesFilter,
};
use bindizr_db::repository::ZoneFilter;

use super::ZoneService;

impl ZoneService {
    pub async fn find(zone_name: &str) -> Result<Option<Zone>, ServiceError> {
        RepositoryService::get_zone_by_name(zone_name).await
    }

    pub async fn find_tx(
        tx: &mut RepositoryTx<'_>,
        zone_name: &str,
    ) -> Result<Option<Zone>, ServiceError> {
        RepositoryService::get_zone_by_name_tx(tx, zone_name).await
    }

    pub async fn find_by_id(zone_id: i32) -> Result<Option<Zone>, ServiceError> {
        RepositoryService::get_zone_by_id(zone_id).await
    }

    pub async fn get_changes_between_serials(
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneChange>, ServiceError> {
        RepositoryService::get_zone_changes_between_serials(zone_id, from_serial, to_serial).await
    }

    pub async fn list() -> Result<Vec<Zone>, ServiceError> {
        RepositoryService::get_all_zones().await.map_err(|e| {
            log_error!("Failed to fetch zones: {}", e);
            ServiceError::Internal("Failed to fetch zones".to_string())
        })
    }

    pub async fn list_by_filter(filter: GetZonesFilter) -> Result<Vec<Zone>, ServiceError> {
        RepositoryService::get_zones_by_filter(ZoneFilter {
            name: filter.name,
            id: filter.id,
            primary_ns: filter.primary_ns,
            admin_email: filter.admin_email,
            ttl: filter.ttl,
            min_ttl: filter.min_ttl,
            max_ttl: filter.max_ttl,
            serial: filter.serial,
            search: filter.search,
        })
        .await
    }

    pub async fn get_by_name(zone_name: &str) -> Result<Zone, ServiceError> {
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
