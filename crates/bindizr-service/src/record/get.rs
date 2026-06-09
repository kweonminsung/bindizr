use bindizr_core::dns::record::{display_record_owner_name, display_record_value};
use bindizr_db::repository::RecordFilter;

use super::RecordService;
use crate::{
    RepositoryTx,
    error::ServiceError,
    log_error,
    model::record::{Record, RecordType, RecordWithZone},
    pagination::paginate_items,
    repository::RepositoryService,
    types::{GetRecordsFilter, PaginatedResponse, Pagination},
};

impl RecordService {
    pub async fn list_by_zone_id(zone_id: i32) -> Result<Vec<Record>, ServiceError> {
        RepositoryService::get_records_by_zone_id(zone_id).await
    }

    pub async fn list_by_zone_id_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<Vec<Record>, ServiceError> {
        RepositoryService::get_records_by_zone_id_tx(tx, zone_id).await
    }

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

    pub async fn list(zone_name: Option<String>) -> Result<Vec<Record>, ServiceError> {
        match zone_name {
            Some(name) => {
                // Check if zone exists and get zone_id
                let zone = match RepositoryService::get_zone_by_name(&name).await {
                    Ok(Some(z)) => z,
                    Ok(None) => {
                        return Err(ServiceError::BadRequest(format!(
                            "Zone with name '{}' not found",
                            name
                        )));
                    }
                    Err(e) => {
                        log_error!("Failed to fetch zone: {}", e);
                        return Err(ServiceError::Internal("Failed to fetch zone".to_string()));
                    }
                };

                // Fetch records by zone_id
                match RepositoryService::get_records_by_zone_id(zone.id).await {
                    Ok(records) => Ok(records),
                    Err(e) => {
                        log_error!("Failed to fetch records for zone {}: {}", name, e);
                        Err(ServiceError::Internal(format!(
                            "Failed to fetch records for zone {}",
                            name
                        )))
                    }
                }
            }
            None => {
                // Fetch all records
                match RepositoryService::get_all_records().await {
                    Ok(records) => Ok(records),
                    Err(e) => {
                        log_error!("Failed to fetch all records: {}", e);
                        Err(ServiceError::Internal(
                            "Failed to fetch all records".to_string(),
                        ))
                    }
                }
            }
        }
    }

    pub async fn list_with_zone(
        zone_name: Option<String>,
    ) -> Result<Vec<RecordWithZone>, ServiceError> {
        match zone_name {
            Some(name) => {
                let zone = match RepositoryService::get_zone_by_name(&name).await {
                    Ok(Some(z)) => z,
                    Ok(None) => {
                        return Err(ServiceError::BadRequest(format!(
                            "Zone with name '{}' not found",
                            name
                        )));
                    }
                    Err(e) => {
                        log_error!("Failed to fetch zone: {}", e);
                        return Err(ServiceError::Internal("Failed to fetch zone".to_string()));
                    }
                };

                match RepositoryService::get_records_by_zone_id_with_zone(zone.id).await {
                    Ok(records) => Ok(records),
                    Err(e) => {
                        log_error!("Failed to fetch records for zone {}: {}", name, e);
                        Err(ServiceError::Internal(format!(
                            "Failed to fetch records for zone {}",
                            name
                        )))
                    }
                }
            }
            None => match RepositoryService::get_all_records_with_zone().await {
                Ok(records) => Ok(records),
                Err(e) => {
                    log_error!("Failed to fetch all records: {}", e);
                    Err(ServiceError::Internal(
                        "Failed to fetch all records".to_string(),
                    ))
                }
            },
        }
    }

    pub async fn list_with_zone_by_filter(
        filter: GetRecordsFilter,
    ) -> Result<PaginatedResponse<RecordWithZone>, ServiceError> {
        let zone_name = filter.resolved_zone_name().map(normalize_filter_zone_name);
        let value_filter = filter.value.clone();
        let search_filter = filter.search.clone();
        let limit = filter.limit;
        let offset = filter.offset;

        if let Some(name) = zone_name.as_deref() {
            match RepositoryService::get_zone_by_name(name).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return Err(ServiceError::BadRequest(format!(
                        "Zone with name '{}' not found",
                        name
                    )));
                }
                Err(e) => {
                    log_error!("Failed to fetch zone: {}", e);
                    return Err(ServiceError::Internal("Failed to fetch zone".to_string()));
                }
            }
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
        let offset = offset.unwrap_or(0);
        let limit = limit.unwrap_or_else(|| total.min(u64::from(u32::MAX)) as u32);

        Ok(PaginatedResponse {
            items: records,
            pagination: Pagination {
                limit,
                offset,
                total,
            },
        })
    }

    pub async fn get_by_id(record_id: i32) -> Result<Record, ServiceError> {
        match RepositoryService::get_record_by_id(record_id).await {
            Ok(Some(record)) => Ok(record),
            Ok(None) => Err(ServiceError::NotFound(format!(
                "Record with id '{}' not found",
                record_id
            ))),
            Err(e) => {
                log_error!("Failed to fetch record: {}", e);
                Err(ServiceError::Internal("Failed to fetch record".to_string()))
            }
        }
    }

    pub async fn get_by_id_with_zone(record_id: i32) -> Result<RecordWithZone, ServiceError> {
        match RepositoryService::get_record_by_id_with_zone(record_id).await {
            Ok(Some(record)) => Ok(record),
            Ok(None) => Err(ServiceError::NotFound(format!(
                "Record with id '{}' not found",
                record_id
            ))),
            Err(e) => {
                log_error!("Failed to fetch record: {}", e);
                Err(ServiceError::Internal("Failed to fetch record".to_string()))
            }
        }
    }
}

fn normalize_filter_zone_name(name: String) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
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
mod tests {
    use chrono::Utc;

    use super::matches_record_search;
    use crate::model::record::{Record, RecordType};

    fn test_record() -> Record {
        Record {
            id: 1,
            name: "www".to_string(),
            record_type: RecordType::A,
            value: "192.0.2.10".to_string(),
            ttl: Some(3600),
            priority: None,
            created_at: Utc::now(),
            zone_id: 1,
        }
    }

    #[test]
    fn matches_record_search_treats_empty_search_as_no_filter() {
        let record = test_record();

        assert!(matches_record_search(
            &record,
            "example.com",
            "www.example.com.",
            "192.0.2.10",
            Some("")
        ));
        assert!(matches_record_search(
            &record,
            "example.com",
            "www.example.com.",
            "192.0.2.10",
            Some(".")
        ));
    }

    #[test]
    fn matches_record_search_still_filters_non_empty_searches() {
        let record = test_record();

        assert!(matches_record_search(
            &record,
            "example.com",
            "www.example.com.",
            "192.0.2.10",
            Some("www")
        ));
        assert!(!matches_record_search(
            &record,
            "example.com",
            "www.example.com.",
            "192.0.2.10",
            Some("missing")
        ));
    }
}
