use bindizr_db::repository::RecordFilter;

use super::RecordService;
use crate::{
    RepositoryTx,
    authorization::Caller,
    error::ServiceError,
    log_error,
    model::record::{Record, RecordType, RecordWithZone},
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
    pub async fn list_by_zone_id_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<Vec<Record>, ServiceError> {
        RepositoryService::get_records_by_zone_id_tx(tx, zone_id).await
    }

    /// Find a single matching record within the caller's transaction.
    pub async fn find_matching_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: Option<i32>,
        name: &str,
        record_type: &RecordType,
        value: Option<&str>,
        priority: Option<i32>,
        match_priority: bool,
    ) -> Result<Option<Record>, ServiceError> {
        RepositoryService::find_record_matching_tx(
            tx,
            zone_id,
            name,
            record_type,
            value,
            priority,
            match_priority,
        )
        .await
    }

    /// List records for a zone by name, or all records when `None`.
    pub async fn list(zone_name: Option<String>) -> Result<Vec<Record>, ServiceError> {
        match zone_name {
            Some(name) => {
                let zone = ZoneService::get_by_name(&name).await?;

                match RepositoryService::get_records_by_zone_id(zone.id).await {
                    Ok(records) => Ok(records),
                    Err(e) => {
                        log_error!("Failed to fetch records for zone {}: {}", name, e);
                        Err(ServiceError::internal(format!(
                            "Failed to fetch records for zone {}",
                            name
                        )))
                    }
                }
            }
            None => match RepositoryService::get_all_records().await {
                Ok(records) => Ok(records),
                Err(e) => {
                    log_error!("Failed to fetch all records: {}", e);
                    Err(ServiceError::internal(
                        "Failed to fetch all records".to_string(),
                    ))
                }
            },
        }
    }

    /// [`Self::list_with_zone_by_filter`] restricted to the caller's visible
    /// zones, pushed into SQL so pagination stays database-side. A filter
    /// naming an unknown or invisible zone reads as an empty page.
    pub async fn list_with_zone_by_filter_for(
        caller: &Caller,
        filter: GetRecordsFilter,
    ) -> Result<PaginatedResponse<RecordWithZone>, ServiceError> {
        let Some(visible) = caller.visible_zone_ids() else {
            return Self::list_with_zone_by_filter(filter).await;
        };

        let mut zone_ids: Vec<i32> = visible.into_iter().collect();
        zone_ids.sort_unstable();
        Self::list_filtered(filter, Some(zone_ids)).await
    }

    /// [`Self::get_by_id_with_zone`] with invisible zones reading as a
    /// missing record, so scoped tokens cannot probe other zones' record ids.
    pub async fn get_by_id_with_zone_for(
        caller: &Caller,
        record_id: i32,
    ) -> Result<RecordWithZone, ServiceError> {
        let record = Self::get_by_id_with_zone(record_id).await?;
        if !caller.zone_visible(record.zone_id) {
            return Err(ServiceError::record_not_found(record_id));
        }
        Ok(record)
    }

    /// List records with their zone name matching `filter`, returning a paginated response.
    pub async fn list_with_zone_by_filter(
        filter: GetRecordsFilter,
    ) -> Result<PaginatedResponse<RecordWithZone>, ServiceError> {
        Self::list_filtered(filter, None).await
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
            ZoneService::get_by_name(name).await?;
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

    /// Fetch a record with its zone name by id, returning `NotFound` if it does not exist.
    pub async fn get_by_id_with_zone(record_id: i32) -> Result<RecordWithZone, ServiceError> {
        match RepositoryService::get_record_by_id_with_zone(record_id).await {
            Ok(Some(record)) => Ok(record),
            Ok(None) => Err(ServiceError::record_not_found(record_id)),
            Err(e) => {
                log_error!("Failed to fetch record: {}", e);
                Err(ServiceError::internal("Failed to fetch record".to_string()))
            }
        }
    }
}

fn normalize_filter_record_name(name: Option<String>, zone_name: Option<&str>) -> Option<String> {
    name.map(|name| {
        let trimmed = name.trim();
        let Some(zone_name) = zone_name else {
            return trimmed.to_string();
        };

        let zone_fqdn = format!("{}.", zone_name);
        let candidate = if trimmed.ends_with('.') {
            trimmed.to_ascii_lowercase()
        } else {
            format!("{}.", trimmed.to_ascii_lowercase())
        };

        if candidate == zone_fqdn || candidate.ends_with(&format!(".{}", zone_fqdn)) {
            candidate
        } else {
            trimmed.to_string()
        }
    })
}
