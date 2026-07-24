use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query},
    http::StatusCode,
    response::IntoResponse,
    routing,
};
use bindizr_service::record::RecordService;
use serde::Deserialize;
use serde_json::json;

use crate::api::{
    error::ApiError,
    middleware::body_parser::{JsonBody, MAX_UPLOAD_BODY_BYTES},
    types::{
        BulkRecordsResponse, CreateBulkRecordsRequest, CreateRecordRequest, ErrorResponse,
        GetRecordResponse, GetRecordsFilter, MessageResponse, RecordListResponse, RecordResponse,
        UpdateRecordRequest,
    },
};

/// Route group for record endpoints.
pub(crate) struct RecordApi;

impl RecordApi {
    /// Build the router for record endpoints.
    pub(crate) async fn routes() -> Router {
        Router::new()
            .route("/records", routing::get(get_records))
            .route("/records/{record_id}", routing::get(get_record))
            .route("/records", routing::post(create_record))
            .route("/records/{record_id}", routing::put(update_record))
            .route("/records/{record_id}", routing::delete(delete_record))
            .route(
                "/zones/{zone_name}/records/bulk",
                routing::post(create_records_bulk)
                    .layer(DefaultBodyLimit::max(MAX_UPLOAD_BODY_BYTES)),
            )
    }
}

#[utoipa::path(
        get,
        path = "/records",
        tag = "Record",
        summary = "List all DNS records",
        params(
            ("zone_name" = Option<String>, Query, description = "The name of the DNS zone to filter records by."),
            ("name" = Option<String>, Query, description = "Filter by record name."),
            ("record_type" = Option<String>, Query, description = "Filter by record type."),
            ("value" = Option<String>, Query, description = "Partially filter by record value."),
            ("ttl" = Option<i32>, Query, description = "Filter by TTL."),
            ("min_ttl" = Option<i32>, Query, description = "Filter by minimum TTL."),
            ("max_ttl" = Option<i32>, Query, description = "Filter by maximum TTL."),
            ("priority" = Option<i32>, Query, description = "Filter by priority."),
            ("min_priority" = Option<i32>, Query, description = "Filter by minimum priority."),
            ("max_priority" = Option<i32>, Query, description = "Filter by maximum priority."),
            ("search" = Option<String>, Query, description = "Partially search records."),
            ("limit" = Option<u32>, Query, description = "Maximum number of records to return."),
            ("offset" = Option<u64>, Query, description = "Number of records to skip.")
        ),
        responses(
            (status = 200, description = "A list of DNS records", body = RecordListResponse),
            (status = 400, description = "Bad request, invalid pagination", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// List DNS records, optionally filtered and paginated.
pub(crate) async fn get_records(Query(query): Query<GetRecordsFilter>) -> impl IntoResponse {
    let raw_records = match RecordService::list_with_zone_by_filter(query).await {
        Ok(records) => records,
        Err(err) => return ApiError::from(err).into_response(),
    };

    let records = raw_records
        .items
        .iter()
        .map(GetRecordResponse::from_record_with_zone)
        .collect::<Vec<_>>();

    let json_body = json!({ "items": records, "pagination": raw_records.pagination });
    (StatusCode::OK, Json(json_body)).into_response()
}

#[utoipa::path(
        get,
        path = "/records/{record_id}",
        tag = "Record",
        summary = "Get a specific DNS record",
        params(
            ("record_id" = i32, Path, description = "The ID of the DNS record to retrieve.")
        ),
        responses(
            (status = 200, description = "Details of the DNS record", body = RecordResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Record not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Get a single DNS record by ID.
pub(crate) async fn get_record(Path(params): Path<RecordIdParam>) -> impl IntoResponse {
    let raw_record = match RecordService::get_by_id_with_zone(params.record_id).await {
        Ok(record) => record,
        Err(err) => return ApiError::from(err).into_response(),
    };

    let record = GetRecordResponse::from_record_with_zone(&raw_record);

    let json_body = json!({ "record": record });
    (StatusCode::OK, Json(json_body)).into_response()
}

#[utoipa::path(
        post,
        path = "/records",
        tag = "Record",
        summary = "Create a new DNS record",
        request_body = CreateRecordRequest,
        responses(
            (status = 201, description = "DNS record created successfully", body = RecordResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Create a new DNS record.
pub(crate) async fn create_record(
    JsonBody(body): JsonBody<CreateRecordRequest>,
) -> impl IntoResponse {
    let raw_record = match RecordService::create(&body).await {
        Ok(record) => record,
        Err(err) => return ApiError::from(err).into_response(),
    };

    let record = GetRecordResponse::from_record_with_zone(&raw_record);

    let json_body = json!({ "record": record });
    (StatusCode::CREATED, Json(json_body)).into_response()
}

#[utoipa::path(
        put,
        path = "/records/{record_id}",
        tag = "Record",
        summary = "Update a specific DNS record",
        params(
            ("record_id" = i32, Path, description = "The ID of the DNS record to update.")
        ),
        request_body = UpdateRecordRequest,
        responses(
            (status = 200, description = "DNS record updated successfully", body = RecordResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Record not found", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Update an existing DNS record.
pub(crate) async fn update_record(
    Path(params): Path<RecordIdParam>,
    JsonBody(body): JsonBody<UpdateRecordRequest>,
) -> impl IntoResponse {
    let raw_record = match RecordService::update_by_id(params.record_id, &body).await {
        Ok(record) => record,
        Err(err) => return ApiError::from(err).into_response(),
    };

    let record = GetRecordResponse::from_record_with_zone(&raw_record);

    let json_body = json!({ "record": record });
    (StatusCode::OK, Json(json_body)).into_response()
}

#[utoipa::path(
        delete,
        path = "/records/{record_id}",
        tag = "Record",
        summary = "Delete a specific DNS record",
        params(
            ("record_id" = i32, Path, description = "The ID of the DNS record to delete.")
        ),
        responses(
            (status = 200, description = "DNS record deleted successfully", body = MessageResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Record not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Delete a DNS record.
pub(crate) async fn delete_record(Path(params): Path<RecordIdParam>) -> impl IntoResponse {
    match RecordService::delete_by_id(params.record_id).await {
        Ok(_) => {
            let json_body = json!({ "message": "Record deleted successfully" });
            (StatusCode::OK, Json(json_body)).into_response()
        }
        Err(err) => ApiError::from(err).into_response(),
    }
}

#[utoipa::path(
        post,
        path = "/zones/{zone_name}/records/bulk",
        tag = "Record",
        summary = "Bulk insert DNS records into a zone",
        description = "Insert many records into a single zone in one transaction. The zone serial is incremented once and a single NOTIFY is sent. Either all records are inserted or none are. With dry_run the same validation runs but nothing is applied.",
        params(
            ("zone_name" = String, Path, description = "The name of the DNS zone to insert records into.")
        ),
        request_body = CreateBulkRecordsRequest,
        responses(
            (status = 201, description = "DNS records created successfully", body = BulkRecordsResponse),
            (status = 200, description = "Dry run validated successfully, nothing applied", body = BulkRecordsResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Bulk insert DNS records into a zone in a single transaction.
pub(crate) async fn create_records_bulk(
    Path(params): Path<ZoneScopedParam>,
    JsonBody(body): JsonBody<CreateBulkRecordsRequest>,
) -> impl IntoResponse {
    let (raw_records, diff) =
        match RecordService::create_bulk(&params.zone_name, &body.records, body.dry_run).await {
            Ok(result) => result,
            Err(err) => return ApiError::from(err).into_response(),
        };

    let records = raw_records
        .iter()
        .map(GetRecordResponse::from_record_with_zone)
        .collect::<Vec<_>>();

    let response = BulkRecordsResponse {
        applied: !body.dry_run,
        dry_run: body.dry_run,
        inserted: if body.dry_run { 0 } else { records.len() },
        records,
        diff,
    };
    let status = if body.dry_run {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    (status, Json(response)).into_response()
}

/// Path parameters scoped to a zone.
#[derive(Debug, Deserialize)]
pub(crate) struct ZoneScopedParam {
    zone_name: String,
}

/// Path parameters addressing a record by id.
#[derive(Debug, Deserialize)]
pub(crate) struct RecordIdParam {
    record_id: i32,
}
