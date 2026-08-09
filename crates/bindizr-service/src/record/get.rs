use bindizr_core::dns::name::{OwnerName, ZoneName};
use bindizr_db::repository::RecordFilter;

use super::RecordService;
use crate::{
    RepositoryTx,
    authorization::Caller,
    error::ServiceError,
    log_error,
    model::record::{Record, RecordWithZone},
    pagination::paginated_response,
    repository::RepositoryService,
    types::{GetRecordsFilter, PaginatedResponse},
    zone::{ZoneService, validation::normalize_zone_name},
};

impl RecordService {
    /// List all records in a zone by zone id.
    pub async fn list_by_zone_id(zone_id: i32) -> Result<Vec<Record>, ServiceError> {
        RepositoryService::get_records_by_zone_id(zone_id).await
    }

    /// List all records in a zone by zone id, within the caller's transaction.
    pub(crate) async fn list_by_zone_id_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<Vec<Record>, ServiceError> {
        RepositoryService::get_records_by_zone_id_tx(tx, zone_id).await
    }

    /// List a zone's records for `caller`; a zone it cannot see reads as
    /// `NotFound`.
    pub async fn list_in_zone(
        caller: &Caller,
        zone_name: &str,
    ) -> Result<Vec<Record>, ServiceError> {
        let zone = ZoneService::get_by_name(caller, zone_name).await?;
        RepositoryService::get_records_by_zone_id(zone.id)
            .await
            .map_err(|e| {
                log_error!("Failed to fetch records for zone {}: {}", zone_name, e);
                ServiceError::internal(format!("Failed to fetch records for zone {}", zone_name))
            })
    }

    /// List records with their zone name matching `filter`, restricted to the
    /// caller's visible zones in SQL so pagination stays database-side. A
    /// filter naming an unknown or invisible zone reads as an empty page.
    pub async fn list_with_zone_by_filter(
        caller: &Caller,
        filter: GetRecordsFilter,
    ) -> Result<PaginatedResponse<RecordWithZone>, ServiceError> {
        let zone_ids = caller.visible_zone_ids().map(|visible| {
            let mut zone_ids: Vec<i32> = visible.into_iter().collect();
            zone_ids.sort_unstable();
            zone_ids
        });
        Self::list_filtered(filter, zone_ids).await
    }

    async fn list_filtered(
        filter: GetRecordsFilter,
        zone_ids: Option<Vec<i32>>,
    ) -> Result<PaginatedResponse<RecordWithZone>, ServiceError> {
        let zone_name = filter
            .zone_name
            .as_deref()
            .map(normalize_zone_name)
            .transpose()?;
        let limit = filter.limit;
        let offset = filter.offset;

        // Scoped callers read unknown and invisible zones alike as empty
        // pages, so skip the 404 probe.
        if let Some(name) = zone_name.as_deref()
            && zone_ids.is_none()
        {
            ZoneService::lookup_by_name(name).await?;
        }

        let name = normalize_filter_record_name(filter.name, zone_name.as_deref());

        let record_filter = RecordFilter {
            zone_name,
            name,
            record_type: filter.record_type,
            value: filter.value,
            ttl: filter.ttl,
            min_ttl: filter.min_ttl,
            max_ttl: filter.max_ttl,
            priority: filter.priority,
            min_priority: filter.min_priority,
            max_priority: filter.max_priority,
            search: filter.search,
            zone_ids,
            limit,
            offset,
        };

        let total = RepositoryService::count_records_by_filter(record_filter.clone()).await?;
        let records = RepositoryService::get_records_by_filter_with_zone(record_filter).await?;
        Ok(paginated_response(records, limit, offset, total))
    }

    /// Fetch a record by id, returning `NotFound` if it does not exist.
    pub async fn get_by_id(record_id: i32) -> Result<Record, ServiceError> {
        match RepositoryService::get_record_by_id(record_id).await {
            Ok(Some(record)) => Ok(record),
            Ok(None) => Err(ServiceError::record_not_found(record_id)),
            Err(e) => {
                log_error!("Failed to fetch record: {}", e);
                Err(ServiceError::internal("Failed to fetch record".to_string()))
            }
        }
    }

    /// Fetch a record with its zone name by id. A record in a zone the caller
    /// cannot see reads as `NotFound`, so ids cannot be probed.
    pub async fn get_by_id_with_zone(
        caller: &Caller,
        record_id: i32,
    ) -> Result<RecordWithZone, ServiceError> {
        let record = match RepositoryService::get_record_by_id_with_zone(record_id).await {
            Ok(Some(record)) => record,
            Ok(None) => return Err(ServiceError::record_not_found(record_id)),
            Err(e) => {
                log_error!("Failed to fetch record: {}", e);
                return Err(ServiceError::internal("Failed to fetch record".to_string()));
            }
        };

        if !caller.zone_visible(record.zone_id) {
            return Err(ServiceError::record_not_found(record_id));
        }
        Ok(record)
    }
}

fn normalize_filter_record_name(name: Option<String>, zone_name: Option<&str>) -> Option<String> {
    name.map(|name| {
        let trimmed = name.trim();
        let Some(zone_name) = zone_name else {
            return trimmed.to_string();
        };

        // An in-zone name is matched in its absolute form; anything else is
        // passed through so the filter can still match it literally.
        let zone = ZoneName::from_row(zone_name);
        match OwnerName::parse_absolute_in_zone(trimmed, &zone) {
            Ok(owner) => owner.to_fqdn(&zone),
            Err(_) => trimmed.to_string(),
        }
    })
}
