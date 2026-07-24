use bindizr_service::{error::ServiceError, record::RecordService};
use serde_json::json;

use crate::{
    api::types::{
        BulkRecordsResponse, CreateBulkRecordsRequest, CreateRecordRequest, GetRecordResponse,
        GetRecordsFilter, UpdateRecordRequest,
    },
    socket::{server::to_response_data, types::DaemonResponse},
};

fn parse_record_id(data: &serde_json::Value) -> Result<i32, ServiceError> {
    let record_id_i64 = data
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| ServiceError::invalid_input("Missing or invalid 'id' field"))?;
    let record_id = i32::try_from(record_id_i64)
        .map_err(|_| ServiceError::invalid_input("Record ID is out of range"))?;
    if record_id < 0 {
        return Err(ServiceError::invalid_input(
            "Record ID must be non-negative",
        ));
    }
    Ok(record_id)
}

/// Handle the `GetRecord` command by returning a record by ID.
pub(super) async fn get_record(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let record_id = parse_record_id(data)?;

    match RecordService::get_by_id_with_zone(record_id).await {
        Ok(record) => {
            let response = GetRecordResponse::from_record_with_zone(&record);
            Ok(DaemonResponse {
                message: "Record retrieved successfully".to_string(),
                data: to_response_data(response)?,
            })
        }
        Err(e) => Err(e),
    }
}

/// Handle the `ListRecords` command by returning records matching the filter.
pub(super) async fn list_records(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let filter = if data.is_null() {
        GetRecordsFilter::default()
    } else {
        serde_json::from_value(data.clone())
            .map_err(|e| ServiceError::invalid_input(format!("Invalid filter data: {}", e)))?
    };

    match RecordService::list_with_zone_by_filter(filter).await {
        Ok(records) => {
            let response = records
                .items
                .iter()
                .map(GetRecordResponse::from_record_with_zone)
                .collect::<Vec<_>>();

            Ok(DaemonResponse {
                message: format!("Found {} record(s)", response.len()),
                data: json!({
                    "items": response,
                    "pagination": records.pagination,
                }),
            })
        }
        Err(e) => Err(e),
    }
}

/// Handle the `CreateRecord` command by creating a new record.
pub(super) async fn create_record(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let request: CreateRecordRequest = serde_json::from_value(data.clone())
        .map_err(|e| ServiceError::invalid_input(format!("Invalid request data: {}", e)))?;

    match RecordService::create(&request).await {
        Ok(record) => {
            let response = GetRecordResponse::from_record_with_zone(&record);

            Ok(DaemonResponse {
                message: "Record created successfully".to_string(),
                data: to_response_data(response)?,
            })
        }
        Err(e) => Err(e),
    }
}

/// Handle the `UpdateRecord` command, merging the payload over the current
/// record so the CLI can send only the flags the user set. The value comes
/// from the stored (non-display) form so MX/SRV round-trip.
pub(super) async fn update_record(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let record_id = parse_record_id(data)?;
    let record = RecordService::get_by_id_with_zone(record_id)
        .await?
        .record();

    let name = data
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| record.name.clone());
    let record_type = data
        .get("record_type")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| record.record_type.to_string());
    let value = match data.get("value") {
        Some(value) if !value.is_null() => serde_json::from_value(value.clone())
            .map_err(|e| ServiceError::invalid_input(format!("Invalid value: {}", e)))?,
        _ => GetRecordResponse::from_record(&record).value,
    };
    // Absent or null (an unset CLI flag) keeps the current value.
    let merged_i32 = |field: &str, current: Option<i32>| -> Option<i32> {
        match data.get(field).and_then(|v| v.as_i64()) {
            Some(value) => Some(value as i32),
            None => current,
        }
    };

    // Only MX/SRV carry a priority; changing the type to any other one clears
    // it, so retyping a record (e.g. MX -> A) isn't blocked by a stale priority.
    let takes_priority =
        record_type.eq_ignore_ascii_case("MX") || record_type.eq_ignore_ascii_case("SRV");
    let priority = if takes_priority {
        merged_i32("priority", record.priority)
    } else {
        None
    };

    let request = UpdateRecordRequest {
        name,
        record_type,
        value,
        ttl: merged_i32("ttl", record.ttl),
        priority,
    };

    match RecordService::update_by_id(record_id, &request).await {
        Ok(record) => Ok(DaemonResponse {
            message: "Record updated successfully".to_string(),
            data: to_response_data(GetRecordResponse::from_record_with_zone(&record))?,
        }),
        Err(e) => Err(e),
    }
}

/// Handle the `BulkCreateRecords` command by inserting records into a zone in
/// a single transaction.
pub(super) async fn bulk_create_records(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let zone_name = super::required_zone_name(data)?;
    let request: CreateBulkRecordsRequest = serde_json::from_value(data.clone())
        .map_err(|e| ServiceError::invalid_input(format!("Invalid request data: {}", e)))?;

    match RecordService::create_bulk(zone_name, &request.records, request.dry_run).await {
        Ok((records, diff)) => {
            let records = records
                .iter()
                .map(GetRecordResponse::from_record_with_zone)
                .collect::<Vec<_>>();

            let message = if request.dry_run {
                format!(
                    "Dry run: {} record(s) validated; nothing applied",
                    records.len()
                )
            } else {
                format!("Inserted {} record(s)", records.len())
            };
            let response = BulkRecordsResponse {
                applied: !request.dry_run,
                dry_run: request.dry_run,
                inserted: if request.dry_run { 0 } else { records.len() },
                records,
                diff,
            };

            Ok(DaemonResponse {
                message,
                data: to_response_data(response)?,
            })
        }
        Err(e) => Err(e),
    }
}

/// Handle the `DeleteRecord` command by deleting a record by ID.
pub(super) async fn delete_record(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let record_id = parse_record_id(data)?;

    match RecordService::delete_by_id(record_id).await {
        Ok(_) => Ok(DaemonResponse {
            message: format!("Record '{}' deleted successfully", record_id),
            data: json!(null),
        }),
        Err(e) => Err(e),
    }
}
