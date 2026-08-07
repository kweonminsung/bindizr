use bindizr_core::dns::record::{display_record_owner_name, display_record_value};
use bindizr_db::repository::RecordFilter;

use super::RecordService;
use crate::{
    RepositoryTx,
    authorization::{Caller, visible_zone_ids, zone_visible},
    error::ServiceError,
    log_error,
    model::{
        record::{Record, RecordType, RecordWithZone},
        zone::Zone,
    },
    pagination::{paginate_items, paginated_response},
    repository::RepositoryService,
    types::{GetRecordsFilter, PaginatedResponse},
    zone::validation::normalize_zone_name,
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
    pub async fn find_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: Option<i32>,
        name: &str,
        record_type: &RecordType,
        value: Option<&str>,
        priority: Option<i32>,
        match_priority: bool,
    ) -> Result<Option<Record>, ServiceError> {
        RepositoryService::get_record_tx(
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
                let lookup_name = normalize_zone_name(&name)?;
                let zone = require_zone_by_name(&lookup_name, &name).await?;

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
    /// zones. Queries stay zone-scoped in SQL (one query per granted zone);
    /// a filter naming an invisible zone reads as an empty page.
    pub async fn list_with_zone_by_filter_for(
        caller: &Caller,
        filter: GetRecordsFilter,
    ) -> Result<PaginatedResponse<RecordWithZone>, ServiceError> {
        let Some(visible) = visible_zone_ids(caller) else {
            return Self::list_with_zone_by_filter(filter).await;
        };

        let limit = filter.limit;
        let offset = filter.offset;

        let zones = RepositoryService::get_all_zones().await?;
        let wanted = filter
            .zone_name
            .as_deref()
            .map(normalize_zone_name)
            .transpose()?;
        let target_zones: Vec<&Zone> = zones
            .iter()
            .filter(|zone| visible.contains(&zone.id))
            .filter(|zone| wanted.as_deref().is_none_or(|name| zone.name == name))
            .collect();

        let mut records: Vec<RecordWithZone> = Vec::new();
        for zone in target_zones {
            let page = Self::list_with_zone_by_filter(GetRecordsFilter {
                zone_name: Some(zone.name.clone()),
                limit: None,
                offset: None,
                ..filter.clone()
            })
            .await?;
            records.extend(page.items);
        }

        records.sort_by(|a, b| (&a.zone_name, &a.name, a.id).cmp(&(&b.zone_name, &b.name, b.id)));
        Ok(paginate_items(records, limit, offset))
    }

    /// [`Self::get_by_id_with_zone`] with invisible zones reading as a
    /// missing record, so scoped tokens cannot probe other zones' record ids.
    pub async fn get_by_id_with_zone_for(
        caller: &Caller,
        record_id: i32,
    ) -> Result<RecordWithZone, ServiceError> {
        let record = Self::get_by_id_with_zone(record_id).await?;
        if !zone_visible(caller, record.zone_id) {
            return Err(ServiceError::record_not_found(record_id));
        }
        Ok(record)
    }

    /// List records with their zone name matching `filter`, returning a paginated response.
    pub async fn list_with_zone_by_filter(
        filter: GetRecordsFilter,
    ) -> Result<PaginatedResponse<RecordWithZone>, ServiceError> {
        let zone_name = filter
            .zone_name
            .as_deref()
            .map(normalize_zone_name)
            .transpose()?;
        let value_filter = filter.value.clone();
        let search_filter = filter.search.clone();
        let limit = filter.limit;
        let offset = filter.offset;

        if let Some(name) = zone_name.as_deref() {
            require_zone_by_name(name, name).await?;
        }

        let name = normalize_filter_record_name(filter.name, zone_name.as_deref());

        let use_display_filters = value_filter.is_some() || search_filter.is_some();
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
            limit: if use_display_filters { None } else { limit },
            offset: if use_display_filters { None } else { offset },
        };

        if use_display_filters {
            let mut records =
                RepositoryService::get_records_by_filter_with_zone(record_filter).await?;
            records.retain(|record| {
                record_matches_display_filters(
                    record,
                    value_filter.as_deref(),
                    search_filter.as_deref(),
                )
            });

            return Ok(paginate_items(records, limit, offset));
        }

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

/// Fetch a zone by (normalized) name, mapping a missing zone to `NotFound` with
/// `display_name` in the message.
async fn require_zone_by_name(lookup_name: &str, display_name: &str) -> Result<Zone, ServiceError> {
    match RepositoryService::get_zone_by_name(lookup_name).await {
        Ok(Some(zone)) => Ok(zone),
        Ok(None) => Err(ServiceError::zone_not_found(display_name)),
        Err(e) => {
            log_error!("Failed to fetch zone: {}", e);
            Err(ServiceError::internal("Failed to fetch zone".to_string()))
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

fn record_matches_display_filters(
    record: &RecordWithZone,
    value_filter: Option<&str>,
    search_filter: Option<&str>,
) -> bool {
    let raw_record = record.record();
    let display_name = display_record_owner_name(&raw_record.name, &record.zone_name);
    let display_value = display_record_value(&raw_record.value, &raw_record.record_type);

    matches_record_value(
        &display_value,
        &raw_record.record_type,
        value_filter.map(str::trim),
    ) && matches_record_search(
        &raw_record,
        &record.zone_name,
        &display_name,
        &display_value,
        search_filter.map(str::trim),
    )
}

fn matches_record_value(actual: &str, record_type: &RecordType, expected: Option<&str>) -> bool {
    expected.is_none_or(|expected| {
        if record_type.is_name_like_value() {
            actual
                .to_ascii_lowercase()
                .contains(&expected.trim_end_matches('.').to_ascii_lowercase())
        } else {
            actual.contains(expected)
        }
    })
}

fn matches_record_search(
    record: &Record,
    zone_name: &str,
    display_name: &str,
    display_value: &str,
    search: Option<&str>,
) -> bool {
    search.is_none_or(|search| {
        let search = search.trim_end_matches('.').to_ascii_lowercase();
        if search.is_empty() {
            return true;
        }

        let record_type = record.record_type.to_string();
        [
            record.name.as_str(),
            display_name,
            zone_name,
            record_type.as_str(),
            display_value,
        ]
        .iter()
        .any(|value| value.to_ascii_lowercase().contains(&search))
    })
}

#[cfg(test)]
mod tests;
