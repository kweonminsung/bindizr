use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_service::{
    record::{ListedRecord, RecordService},
    types::{
        BulkRecordsResponse, CreateBulkRecordsRequest, CreateRecordRequest, ErrorResponse,
        GetRecordResponse, GetRecordsFilter, MessageResponse, PaginatedResponse, RecordItem,
        RecordResponse,
    },
};
use serde::Deserialize;

use crate::api::{
    RequestCaller,
    error::ApiError,
    middleware::body_parser::{JsonBody, MAX_UPLOAD_BODY_BYTES},
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
            ("signed" = Option<bool>, Query, description = "Append the zone's derived DNSSEC records (RRSIG, DNSKEY, NSEC/NSEC3/NSEC3PARAM, CDS, CDNSKEY) after the user records, in the same pagination. Derived rows carry no id; record_type also accepts a derived type, while value, search, and priority filters keep the listing user-only."),
            ("limit" = Option<u32>, Query, description = "Maximum number of records to return."),
            ("offset" = Option<u64>, Query, description = "Number of records to skip.")
        ),
        responses(
            (status = 200, description = "A list of DNS records", body = PaginatedResponse<GetRecordResponse>),
            (status = 400, description = "Bad request, invalid pagination", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// List DNS records, optionally filtered and paginated.
pub(crate) async fn get_records(
    RequestCaller(caller): RequestCaller,
    Query(query): Query<GetRecordsFilter>,
) -> Result<Response, ApiError> {
    let raw_records = RecordService::list_with_zone_by_filter(&caller, query).await?;

    let records = raw_records
        .items
        .iter()
        .map(ListedRecord::to_response)
        .collect::<Vec<_>>();

    let response = PaginatedResponse {
        items: records,
        pagination: raw_records.pagination,
    };
    Ok((StatusCode::OK, Json(response)).into_response())
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
pub(crate) async fn get_record(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<RecordIdParam>,
) -> Result<Response, ApiError> {
    let raw_record = RecordService::get_with_zone(&caller, params.record_id).await?;

    let response = RecordResponse {
        record: GetRecordResponse::from_record_with_zone(&raw_record),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
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
            (status = 403, description = "The token's policies do not allow this record write", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Create a new DNS record.
pub(crate) async fn create_record(
    RequestCaller(caller): RequestCaller,
    JsonBody(body): JsonBody<CreateRecordRequest>,
) -> Result<Response, ApiError> {
    let raw_record = RecordService::create(&caller, &body).await?;

    let response = RecordResponse {
        record: GetRecordResponse::from_record_with_zone(&raw_record),
    };
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

#[utoipa::path(
        put,
        path = "/records/{record_id}",
        tag = "Record",
        summary = "Update a specific DNS record",
        params(
            ("record_id" = i32, Path, description = "The ID of the DNS record to update.")
        ),
        request_body = RecordItem,
        responses(
            (status = 200, description = "DNS record updated successfully", body = RecordResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The token's policies do not allow this record write", body = ErrorResponse),
            (status = 404, description = "Record not found", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Update an existing DNS record.
pub(crate) async fn update_record(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<RecordIdParam>,
    JsonBody(body): JsonBody<RecordItem>,
) -> Result<Response, ApiError> {
    let raw_record = RecordService::update(&caller, params.record_id, &body).await?;

    let response = RecordResponse {
        record: GetRecordResponse::from_record_with_zone(&raw_record),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
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
            (status = 403, description = "The token's policies do not allow this record write", body = ErrorResponse),
            (status = 404, description = "Record not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Delete a DNS record.
pub(crate) async fn delete_record(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<RecordIdParam>,
) -> Result<Response, ApiError> {
    RecordService::delete(&caller, params.record_id).await?;

    let response = MessageResponse {
        message: "Record deleted successfully".to_string(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
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
            (status = 403, description = "The token's policies do not allow this record write", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Bulk insert DNS records into a zone in a single transaction.
pub(crate) async fn create_records_bulk(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneScopedParam>,
    JsonBody(body): JsonBody<CreateBulkRecordsRequest>,
) -> Result<Response, ApiError> {
    let response =
        RecordService::create_bulk(&caller, &params.zone_name, &body.records, body.dry_run).await?;

    let status = if body.dry_run {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((status, Json(response)).into_response())
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
