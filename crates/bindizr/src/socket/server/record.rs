use bindizr_service::{
    authorization::Caller,
    error::ServiceError,
    record::RecordService,
    types::{CreateRecordRequest, GetRecordResponse, GetRecordsFilter},
};
use serde_json::json;

use crate::socket::{
    server::{parse_params, to_response_data},
    types::{BulkCreateRecordsParams, DaemonResponse, RecordIdParams, UpdateRecordParams},
};

/// Handle the `GetRecord` command by returning a record by ID.
pub(crate) async fn get_record(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: RecordIdParams = parse_params(data)?;

    let record = RecordService::get_with_zone(&Caller::Global, params.id).await?;
    Ok(DaemonResponse {
        message: "Record retrieved successfully".to_string(),
        data: to_response_data(GetRecordResponse::from_record_with_zone(&record))?,
    })
}

/// Handle the `ListRecords` command by returning records matching the filter.
pub(crate) async fn list_records(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let filter: GetRecordsFilter = if data.is_null() {
        GetRecordsFilter::default()
    } else {
        parse_params(data)?
    };

    let response = RecordService::list_with_zone_by_filter(&Caller::Global, filter).await?;

    Ok(DaemonResponse {
        message: format!("Found {} record(s)", response.items.len()),
        data: to_response_data(response)?,
    })
}

/// Handle the `CreateRecord` command by creating a new record.
pub(crate) async fn create_record(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let request: CreateRecordRequest = parse_params(data)?;

    let record = RecordService::create(&Caller::Global, &request).await?;
    Ok(DaemonResponse {
        message: "Record created successfully".to_string(),
        data: to_response_data(GetRecordResponse::from_record_with_zone(&record))?,
    })
}

/// Handle the `UpdateRecord` command by applying a partial-update patch.
pub(crate) async fn update_record(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: UpdateRecordParams = parse_params(data)?;

    let record = RecordService::patch(&Caller::Global, params.id, &params.patch).await?;
    Ok(DaemonResponse {
        message: "Record updated successfully".to_string(),
        data: to_response_data(GetRecordResponse::from_record_with_zone(&record))?,
    })
}

/// Handle the `BulkCreateRecords` command by inserting records into a zone in
/// a single transaction.
pub(crate) async fn bulk_create_records(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let BulkCreateRecordsParams { zone_name, request } = parse_params(data)?;

    let response = RecordService::create_bulk(
        &Caller::Global,
        &zone_name,
        &request.records,
        request.dry_run,
    )
    .await?;
    let message = if response.dry_run {
        format!(
            "Dry run: {} record(s) validated; nothing applied",
            response.records.len()
        )
    } else {
        format!("Inserted {} record(s)", response.inserted)
    };

    Ok(DaemonResponse {
        message,
        data: to_response_data(response)?,
    })
}

/// Handle the `DeleteRecord` command by deleting a record by ID.
pub(crate) async fn delete_record(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: RecordIdParams = parse_params(data)?;

    RecordService::delete(&Caller::Global, params.id).await?;
    Ok(DaemonResponse {
        message: format!("Record '{}' deleted successfully", params.id),
        data: json!(null),
    })
}
