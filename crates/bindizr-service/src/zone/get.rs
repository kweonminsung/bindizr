use bindizr_db::repository::ZoneFilter;

use super::{ZoneService, validation::normalize_zone_lookup_name};
use crate::{
    RepositoryTx,
    error::ServiceError,
    log_error,
    model::{zone::Zone, zone_change::ZoneChange},
    repository::RepositoryService,
    types::{GetZonesFilter, PaginatedResponse, Pagination},
};

impl ZoneService {
    pub async fn find(zone_name: &str) -> Result<Option<Zone>, ServiceError> {
        let lookup_name = normalize_zone_lookup_name(zone_name)?;
        RepositoryService::get_zone_by_name(&lookup_name).await
    }

    pub async fn find_tx(
        tx: &mut RepositoryTx<'_>,
        zone_name: &str,
    ) -> Result<Option<Zone>, ServiceError> {
        let lookup_name = normalize_zone_lookup_name(zone_name)?;
        RepositoryService::get_zone_by_name_tx(tx, &lookup_name).await
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

    pub async fn list_by_filter(
        filter: GetZonesFilter,
    ) -> Result<PaginatedResponse<Zone>, ServiceError> {
        let limit = filter.limit;
        let offset = filter.offset;

        let zone_filter = ZoneFilter {
            name: filter.name,
            id: filter.id,
            primary_ns: filter.primary_ns,
            admin_email: filter.admin_email,
            ttl: filter.ttl,
            min_ttl: filter.min_ttl,
            max_ttl: filter.max_ttl,
            serial: filter.serial,
            search: filter.search,
            limit,
            offset,
        };

        let total = RepositoryService::count_zones_by_filter(zone_filter.clone()).await?;
        let zones = RepositoryService::get_zones_by_filter(zone_filter).await?;
        let offset = offset.unwrap_or(0);
        let limit = limit.unwrap_or_else(|| total.min(u64::from(u32::MAX)) as u32);

        Ok(PaginatedResponse {
            items: zones,
            pagination: Pagination {
                limit,
                offset,
                total,
            },
        })
    }

    pub async fn get_by_name(zone_name: &str) -> Result<Zone, ServiceError> {
        let lookup_name = normalize_zone_lookup_name(zone_name)?;

        match RepositoryService::get_zone_by_name(&lookup_name).await {
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
