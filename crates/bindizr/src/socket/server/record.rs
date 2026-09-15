use bindizr_service::{
    authorization::Caller,
    error::ServiceError,
    record::RecordService,
    types::{
        CreateBulkRecordsRequest, CreateRecordRequest, DeleteRecordsFilter, GetRecordResponse,
        GetRecordsFilter, RecordResponse,
    },
};

use crate::socket::{
    server::{parse_params, to_response_data},
    types::{DaemonResponse, RecordIdParams, UpdateRecordParams},
};

/// Return the requested record.
pub(crate) async fn get_record(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: RecordIdParams = parse_params(data)?;

    let record = RecordService::get_with_zone(&Caller::Global, params.id).await?;
    Ok(DaemonResponse {
        message: "Record retrieved successfully".to_string(),
        data: to_response_data(RecordResponse {
            record: GetRecordResponse::from_record_with_zone(&record),
        })?,
    })
}

/// Return records matching the request filters.
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

/// Create a record from the control request.
pub(crate) async fn create_record(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let request: CreateRecordRequest = parse_params(data)?;

    let record = RecordService::create(&Caller::Global, &request).await?;
    Ok(DaemonResponse {
        message: "Record created successfully".to_string(),
        data: to_response_data(RecordResponse {
            record: GetRecordResponse::from_record_with_zone(&record),
        })?,
    })
}

/// Update the requested record.
pub(crate) async fn update_record(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: UpdateRecordParams = parse_params(data)?;

    let record = RecordService::update(&Caller::Global, params.id, &params.request).await?;
    Ok(DaemonResponse {
        message: "Record updated successfully".to_string(),
        data: to_response_data(RecordResponse {
            record: GetRecordResponse::from_record_with_zone(&record),
        })?,
    })
}

/// Preview or apply the requested batch of new records.
pub(crate) async fn bulk_create_records(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let request: CreateBulkRecordsRequest = parse_params(data)?;

    let response = RecordService::create_bulk(
        &Caller::Global,
        &request.zone_name,
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

/// Delete the requested record.
pub(crate) async fn delete_record(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: RecordIdParams = parse_params(data)?;

    RecordService::delete(&Caller::Global, params.id).await?;
    Ok(DaemonResponse {
        message: format!("Record '{}' deleted successfully", params.id),
        data: serde_json::Value::Null,
    })
}

/// Delete records matching the requested owner, type, and value filters.
pub(crate) async fn delete_records_matching(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let filter: DeleteRecordsFilter = parse_params(data)?;
    let response = RecordService::delete_matching(&Caller::Global, &filter).await?;

    Ok(DaemonResponse {
        message: if response.dry_run {
            format!("{} record(s) would be deleted", response.deleted)
        } else {
            format!("{} record(s) deleted", response.deleted)
        },
        data: to_response_data(response)?,
    })
}
