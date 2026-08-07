use bindizr_db::repository::ZoneFilter;

use super::{ZoneService, validation::normalize_zone_name};
use crate::{
    RepositoryTx,
    authorization::{Caller, ensure_zone_visible, visible_zone_ids},
    error::ServiceError,
    log_error,
    model::{zone::Zone, zone_change::ZoneChange},
    pagination::paginated_response,
    repository::RepositoryService,
    types::{GetZonesFilter, PaginatedResponse},
};

impl ZoneService {
    /// Look up a zone by name, returning `None` if it does not exist.
    pub async fn find_by_name(zone_name: &str) -> Result<Option<Zone>, ServiceError> {
        let lookup_name = normalize_zone_name(zone_name)?;
        RepositoryService::get_zone_by_name(&lookup_name).await
    }

    /// Look up a zone by name within the caller's transaction.
    pub async fn find_by_name_tx(
        tx: &mut RepositoryTx<'_>,
        zone_name: &str,
    ) -> Result<Option<Zone>, ServiceError> {
        let lookup_name = normalize_zone_name(zone_name)?;
        RepositoryService::get_zone_by_name_tx(tx, &lookup_name).await
    }

    /// Get the recorded zone changes between two serials, for building an IXFR.
    pub async fn get_changes_between_serials(
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneChange>, ServiceError> {
        RepositoryService::get_zone_changes_between_serials(zone_id, from_serial, to_serial).await
    }

    /// Cheap database round-trip (limit-1 zones probe), for health checks.
    pub async fn ping() -> Result<(), ServiceError> {
        RepositoryService::ping_zones().await
    }

    /// List all zones.
    pub async fn list() -> Result<Vec<Zone>, ServiceError> {
        RepositoryService::get_all_zones().await.map_err(|e| {
            log_error!("Failed to fetch zones: {}", e);
            ServiceError::internal("Failed to fetch zones".to_string())
        })
    }

    /// List zones matching `filter`, returning a paginated response.
    pub async fn list_by_filter(
        filter: GetZonesFilter,
    ) -> Result<PaginatedResponse<Zone>, ServiceError> {
        Self::list_filtered(filter, None).await
    }

    /// [`Self::list_by_filter`] restricted to the caller's visible zones,
    /// pushed into SQL so pagination stays database-side.
    pub async fn list_by_filter_for(
        caller: &Caller,
        filter: GetZonesFilter,
    ) -> Result<PaginatedResponse<Zone>, ServiceError> {
        let Some(visible) = visible_zone_ids(caller) else {
            return Self::list_by_filter(filter).await;
        };

        let mut ids: Vec<i32> = visible.into_iter().collect();
        ids.sort_unstable();
        Self::list_filtered(filter, Some(ids)).await
    }

    async fn list_filtered(
        filter: GetZonesFilter,
        ids: Option<Vec<i32>>,
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
            ids,
            limit,
            offset,
        };

        let total = RepositoryService::count_zones_by_filter(zone_filter.clone()).await?;
        let zones = RepositoryService::get_zones_by_filter(zone_filter).await?;
        Ok(paginated_response(zones, limit, offset, total))
    }

    /// 404 for zones a scoped caller cannot see, so grants cannot be probed.
    pub async fn ensure_visible(caller: &Caller, zone_name: &str) -> Result<(), ServiceError> {
        if caller.is_global() {
            return Ok(());
        }
        let zone = Self::get_by_name(zone_name).await?;
        ensure_zone_visible(caller, &zone)
    }

    /// [`Self::get_by_name`] with scoped-caller visibility applied.
    pub async fn get_by_name_for(caller: &Caller, zone_name: &str) -> Result<Zone, ServiceError> {
        let zone = Self::get_by_name(zone_name).await?;
        ensure_zone_visible(caller, &zone)?;
        Ok(zone)
    }

    /// Fetch a zone by name, returning `NotFound` if it does not exist.
    pub async fn get_by_name(zone_name: &str) -> Result<Zone, ServiceError> {
        let lookup_name = normalize_zone_name(zone_name)?;

        match RepositoryService::get_zone_by_name(&lookup_name).await {
            Ok(Some(zone)) => Ok(zone),
            Ok(None) => Err(ServiceError::zone_not_found(zone_name)),
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                Err(ServiceError::internal("Failed to fetch zone".to_string()))
            }
        }
    }

    /// Fetch (and lock) a zone by name within the caller's transaction,
    /// returning `NotFound` if it does not exist.
    pub async fn get_by_name_tx(
        tx: &mut RepositoryTx<'_>,
        zone_name: &str,
    ) -> Result<Zone, ServiceError> {
        let lookup_name = normalize_zone_name(zone_name)?;
        match RepositoryService::get_zone_by_name_tx(tx, &lookup_name).await {
            Ok(Some(zone)) => Ok(zone),
            Ok(None) => Err(ServiceError::zone_not_found(zone_name)),
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                Err(ServiceError::internal("Failed to fetch zone".to_string()))
            }
        }
    }
}
