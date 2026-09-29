use bindizr_core::model::record::RecordId;
use bindizr_service::{
    Context,
    authorization::Caller,
    error::ServiceError,
    record,
    types::{
        BulkRecordsResponse, CreateBulkRecordsRequest, CreateRecordRequest, DeleteRecordsFilter,
        DeleteRecordsResponse, GetRecordResponse, GetRecordsFilter, PaginatedResponse,
        RecordResponse, RecordWriteResponse, Run, UpdateRecordRequest,
    },
    zone,
};

use crate::socket::types::DaemonResponse;

/// Return the requested record.
pub(crate) async fn get_record(
    cx: &Context,
    id: RecordId,
) -> Result<DaemonResponse<RecordResponse>, ServiceError> {
    let record = record::get_with_zone(cx, &Caller::Global, id).await?;
    Ok(DaemonResponse {
        message: "Record retrieved successfully".to_string(),
        data: RecordResponse {
            record: GetRecordResponse::from(&record),
        },
    })
}

/// Return records matching the request filters.
pub(crate) async fn list_records(
    cx: &Context,
    filter: GetRecordsFilter,
) -> Result<DaemonResponse<PaginatedResponse<GetRecordResponse>>, ServiceError> {
    let response = record::list_with_zone_by_filter(cx, &Caller::Global, filter).await?;
    Ok(DaemonResponse {
        message: "Records retrieved successfully".to_string(),
        data: response,
    })
}

/// Create a record from the control request.
pub(crate) async fn create_record(
    cx: &Context,
    request: &CreateRecordRequest,
) -> Result<DaemonResponse<RecordWriteResponse>, ServiceError> {
    let response = record::create(cx, &Caller::Global, request).await?;
    Ok(DaemonResponse {
        message: if response.dry_run {
            "Record would be created".to_string()
        } else {
            "Record created successfully".to_string()
        },
        data: response,
    })
}

/// Update the requested record.
pub(crate) async fn update_record(
    cx: &Context,
    id: RecordId,
    request: &UpdateRecordRequest,
) -> Result<DaemonResponse<RecordWriteResponse>, ServiceError> {
    let response = record::update(cx, &Caller::Global, id, request).await?;
    Ok(DaemonResponse {
        message: if response.dry_run {
            "Record would be updated".to_string()
        } else {
            "Record updated successfully".to_string()
        },
        data: response,
    })
}

/// Update the one record at the requested owner name.
pub(crate) async fn update_record_by_name(
    cx: &Context,
    zone_name: &str,
    record_name: &str,
    request: &UpdateRecordRequest,
) -> Result<DaemonResponse<RecordWriteResponse>, ServiceError> {
    let response = record::update_by_name(
        cx,
        &Caller::Global,
        &zone::normalize_name(zone_name)?,
        record_name,
        request,
    )
    .await?;
    Ok(DaemonResponse {
        message: if response.dry_run {
            "Record would be updated".to_string()
        } else {
            "Record updated successfully".to_string()
        },
        data: response,
    })
}

/// Preview or apply the requested batch of new records.
pub(crate) async fn create_records_bulk(
    cx: &Context,
    request: &CreateBulkRecordsRequest,
) -> Result<DaemonResponse<BulkRecordsResponse>, ServiceError> {
    let response = record::create_bulk(cx, &Caller::Global, request).await?;
    let message = if response.dry_run {
        format!(
            "Dry run: {} record(s) validated; nothing applied",
            response.records.len()
        )
    } else {
        format!("Added {} record(s)", response.added)
    };
    Ok(DaemonResponse {
        message,
        data: response,
    })
}

/// Delete the requested record. The payload is the body `DELETE
/// /records/{id}` answers with, so `--output json` prints the same one.
pub(crate) async fn delete_record(
    cx: &Context,
    id: RecordId,
    run: Run,
) -> Result<DaemonResponse<DeleteRecordsResponse>, ServiceError> {
    let response = record::delete(cx, &Caller::Global, id, run).await?;
    Ok(DaemonResponse {
        message: if response.dry_run {
            format!("Record {} would be deleted", id)
        } else {
            format!("Record {} deleted successfully", id)
        },
        data: response,
    })
}

/// Delete records matching the requested owner, type, and value filters.
pub(crate) async fn delete_records_matching(
    cx: &Context,
    filter: &DeleteRecordsFilter,
) -> Result<DaemonResponse<DeleteRecordsResponse>, ServiceError> {
    let response = record::delete_matching(cx, &Caller::Global, filter).await?;
    Ok(DaemonResponse {
        message: if response.dry_run {
            format!("{} record(s) would be deleted", response.deleted)
        } else {
            format!("{} record(s) deleted successfully", response.deleted)
        },
        data: response,
    })
}
