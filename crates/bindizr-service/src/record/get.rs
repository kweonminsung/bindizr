use crate::{
    RepositoryTx,
    error::ServiceError,
    log_error,
    model::record::{Record, RecordType, RecordWithZone},
    repository::RepositoryService,
    types::GetRecordsFilter,
};
use bindizr_core::dns::txt;

use super::RecordService;

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

    pub async fn list_with_zone_filtered(
        filter: GetRecordsFilter,
    ) -> Result<Vec<RecordWithZone>, ServiceError> {
        let records = Self::list_with_zone(filter.resolved_zone_name()).await?;
        Ok(records
            .into_iter()
            .filter(|record| record_matches_filter(record, &filter))
            .collect())
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

fn record_matches_filter(record: &RecordWithZone, filter: &GetRecordsFilter) -> bool {
    let raw_record = record.record();
    let display_name = display_record_owner_name(&raw_record.name, &record.zone_name);
    let display_value = display_record_value(&raw_record.value, &raw_record.record_type);

    matches_dns_string(&record.zone_name, filter.resolved_zone_name().as_deref())
        && matches_record_name(&raw_record.name, &display_name, filter.name.as_deref())
        && matches_string(
            &raw_record.record_type.to_string(),
            filter.record_type.as_deref(),
        )
        && matches_record_value(
            &display_value,
            &raw_record.record_type,
            filter.value.as_deref(),
        )
        && matches_optional_i32(raw_record.ttl, filter.ttl)
        && matches_optional_min(raw_record.ttl, filter.min_ttl)
        && matches_optional_max(raw_record.ttl, filter.max_ttl)
        && matches_optional_i32(raw_record.priority, filter.priority)
        && matches_optional_min(raw_record.priority, filter.min_priority)
        && matches_optional_max(raw_record.priority, filter.max_priority)
        && matches_record_search(
            &raw_record,
            &record.zone_name,
            &display_name,
            &display_value,
            filter.search.as_deref(),
        )
}

fn matches_record_search(
    record: &Record,
    zone_name: &str,
    display_name: &str,
    display_value: &str,
    search: Option<&str>,
) -> bool {
    search.is_none_or(|search| {
        let search = search.trim().to_ascii_lowercase();
        let record_type = record.record_type.to_string();
        !search.is_empty()
            && [
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

fn matches_record_name(raw_name: &str, display_name: &str, expected: Option<&str>) -> bool {
    expected.is_none_or(|expected| {
        raw_name.eq_ignore_ascii_case(expected.trim())
            || to_fqdn_lower(display_name) == to_fqdn_lower(expected)
    })
}

fn matches_record_value(actual: &str, record_type: &RecordType, expected: Option<&str>) -> bool {
    expected.is_none_or(|expected| {
        if is_name_like_record_type(record_type) {
            actual
                .to_ascii_lowercase()
                .contains(&expected.trim().to_ascii_lowercase())
        } else {
            actual.contains(expected.trim())
        }
    })
}

fn matches_string(actual: &str, expected: Option<&str>) -> bool {
    expected.is_none_or(|expected| actual.eq_ignore_ascii_case(expected.trim()))
}

fn matches_dns_string(actual: &str, expected: Option<&str>) -> bool {
    expected.is_none_or(|expected| to_fqdn_lower(actual) == to_fqdn_lower(expected))
}

fn matches_optional_i32(actual: Option<i32>, expected: Option<i32>) -> bool {
    expected.is_none_or(|expected| actual == Some(expected))
}

fn matches_optional_min(actual: Option<i32>, expected: Option<i32>) -> bool {
    expected.is_none_or(|expected| actual.is_some_and(|actual| actual >= expected))
}

fn matches_optional_max(actual: Option<i32>, expected: Option<i32>) -> bool {
    expected.is_none_or(|expected| actual.is_some_and(|actual| actual <= expected))
}

fn display_record_owner_name(stored_name: &str, zone_name: &str) -> String {
    let zone_fqdn = to_fqdn_lower(zone_name);
    let trimmed = stored_name.trim();

    if trimmed == "@" {
        return zone_fqdn;
    }

    if trimmed.ends_with('.') {
        return to_fqdn_lower(trimmed);
    }

    let candidate = to_fqdn_lower(trimmed);
    if candidate == zone_fqdn || candidate.ends_with(&format!(".{}", zone_fqdn)) {
        candidate
    } else {
        to_fqdn_lower(&format!("{}.{}", trimmed, zone_fqdn))
    }
}

fn display_record_value(value: &str, record_type: &RecordType) -> String {
    if *record_type == RecordType::TXT {
        return match txt::decode_raw_txt_value(value) {
            Some(txt::DecodedTxtValue::String(value)) => value,
            Some(txt::DecodedTxtValue::Segments(segments)) => segments.join(""),
            None => value.to_string(),
        };
    }

    match record_type {
        RecordType::CNAME | RecordType::NS | RecordType::PTR => to_fqdn_lower(value),
        RecordType::MX | RecordType::SRV => display_last_name_field(value),
        _ => value.to_string(),
    }
}

fn display_last_name_field(value: &str) -> String {
    let mut fields = value
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let Some(last) = fields.pop() else {
        return value.to_string();
    };

    fields.push(to_fqdn_lower(&last));
    fields.join(" ")
}

fn is_name_like_record_type(record_type: &RecordType) -> bool {
    matches!(
        record_type,
        RecordType::CNAME | RecordType::NS | RecordType::PTR | RecordType::MX | RecordType::SRV
    )
}

fn to_fqdn_lower(value: &str) -> String {
    format!(
        "{}.",
        value.trim().trim_end_matches('.').to_ascii_lowercase()
    )
}
