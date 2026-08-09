use bindizr_service::{error::ServiceError, record::RecordService};
use serde_json::json;

use crate::{
    api::types::{BulkRecordsResponse, CreateRecordRequest, GetRecordResponse, GetRecordsFilter},
    socket::{
        server::{parse_params, to_response_data},
        types::{BulkCreateRecordsParams, DaemonResponse, RecordIdParams, UpdateRecordParams},
    },
};

/// Handle the `GetRecord` command by returning a record by ID.
pub(super) async fn get_record(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: RecordIdParams = parse_params(data)?;

    match RecordService::get_by_id_with_zone(params.id).await {
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
    let filter: GetRecordsFilter = if data.is_null() {
        GetRecordsFilter::default()
    } else {
        parse_params(data)?
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
    let request: CreateRecordRequest = parse_params(data)?;

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

/// Handle the `UpdateRecord` command by applying a partial-update patch.
pub(super) async fn update_record(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: UpdateRecordParams = parse_params(data)?;

    match RecordService::patch_by_id(params.id, &params.patch).await {
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
    let BulkCreateRecordsParams { zone_name, request } = parse_params(data)?;

    match RecordService::create_bulk(&zone_name, &request.records, request.dry_run).await {
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
    let params: RecordIdParams = parse_params(data)?;

    match RecordService::delete_by_id(params.id).await {
        Ok(_) => Ok(DaemonResponse {
            message: format!("Record '{}' deleted successfully", params.id),
            data: json!(null),
        }),
        Err(e) => Err(e),
    }
}
