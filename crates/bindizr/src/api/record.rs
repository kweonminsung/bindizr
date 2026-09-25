use axum::{
    Json, Router,
    extract::DefaultBodyLimit,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_service::{
    record::RecordService,
    types::{
        BulkRecordsResponse, CreateBulkRecordsRequest, CreateRecordRequest, DEFAULT_PAGE_LIMIT,
        DeleteRecordsFilter, DeleteRecordsResponse, ErrorResponse, GetRecordResponse,
        GetRecordsFilter, PaginatedResponse, RecordResponse, RecordWriteResponse,
        UpdateRecordRequest,
    },
};

use crate::{
    api::{
        RequestCaller,
        error::{ApiError, Path, Query},
        middleware::body_parser::{JsonBody, MAX_UPLOAD_BODY_BYTES},
        query::DryRunQuery,
    },
    params::IdParams,
};

pub(crate) struct RecordApi;

impl RecordApi {
    /// Build the record API routes.
    pub(crate) async fn routes() -> Router {
        Router::new()
            .route("/records", routing::get(list_records))
            .route("/records/{id}", routing::get(get_record))
            .route("/records", routing::post(create_record))
            .route("/records/{id}", routing::put(update_record))
            .route("/records/{id}", routing::delete(delete_record))
            .route("/records", routing::delete(delete_records_matching))
            .route(
                "/records/bulk",
                routing::post(create_records_bulk)
                    .layer(DefaultBodyLimit::max(MAX_UPLOAD_BODY_BYTES)),
            )
    }
}

/// List DNS records, optionally filtered and paginated.
#[utoipa::path(
        get,
        path = "/records",
        tag = "Record",
        summary = "List all DNS records",
        params(GetRecordsFilter),
        responses(
            (status = 200, description = "A list of DNS records", body = PaginatedResponse<GetRecordResponse>),
            (status = 400, description = "Bad request, invalid pagination", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_records(
    RequestCaller(caller): RequestCaller,
    Query(mut query): Query<GetRecordsFilter>,
) -> Result<Response, ApiError> {
    query.limit = query.limit.or(Some(DEFAULT_PAGE_LIMIT));
    let response = RecordService::list_with_zone_by_filter(&caller, query).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Get a single DNS record by ID.
#[utoipa::path(
        get,
        path = "/records/{id}",
        tag = "Record",
        summary = "Get a specific DNS record",
        params(
            ("id" = i32, Path, description = "The ID of the DNS record to retrieve.")
        ),
        responses(
            (status = 200, description = "Details of the DNS record", body = RecordResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Record not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn get_record(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<IdParams>,
) -> Result<Response, ApiError> {
    let raw_record = RecordService::get_with_zone(&caller, params.id).await?;

    let response = RecordResponse {
        record: GetRecordResponse::from_record_with_zone(&raw_record),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Create a new DNS record.
#[utoipa::path(
        post,
        path = "/records",
        tag = "Record",
        summary = "Create a new DNS record",
        request_body = CreateRecordRequest,
        responses(
            (status = 201, description = "DNS record created successfully", body = RecordWriteResponse),
            (status = 200, description = "Dry run validated successfully, nothing applied", body = RecordWriteResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The token's grants do not allow this record write", body = ErrorResponse),
            (status = 404, description = "Zone not found, or not visible to the token", body = ErrorResponse),
            (status = 409, description = "Record conflict", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn create_record(
    RequestCaller(caller): RequestCaller,
    JsonBody(body): JsonBody<CreateRecordRequest>,
) -> Result<Response, ApiError> {
    let response = RecordService::create(&caller, &body).await?;
    // 201 says a resource now exists; a preview created nothing.
    let status = if response.applied {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(response)).into_response())
}

/// Update an existing DNS record.
#[utoipa::path(
        put,
        path = "/records/{id}",
        tag = "Record",
        summary = "Update a specific DNS record",
        description = "Applies the given fields and keeps the rest. `value` is required when `type` changes, since a stored value is encoded per type.",
        params(
            ("id" = i32, Path, description = "The ID of the DNS record to update.")
        ),
        request_body = UpdateRecordRequest,
        responses(
            (status = 200, description = "DNS record updated successfully", body = RecordWriteResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The token's grants do not allow this record write", body = ErrorResponse),
            (status = 404, description = "Record not found", body = ErrorResponse),
            (status = 409, description = "Record conflict", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn update_record(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<IdParams>,
    JsonBody(body): JsonBody<UpdateRecordRequest>,
) -> Result<Response, ApiError> {
    let response = RecordService::update(&caller, params.id, &body).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Delete a DNS record.
#[utoipa::path(
        delete,
        path = "/records/{id}",
        tag = "Record",
        summary = "Delete a specific DNS record",
        params(
            ("id" = i32, Path, description = "The ID of the DNS record to delete."),
            ("dry_run" = Option<bool>, Query, description = "Report what would go without removing it.")
        ),
        responses(
            (status = 200, description = "DNS record deleted successfully", body = DeleteRecordsResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The token's grants do not allow this record write", body = ErrorResponse),
            (status = 404, description = "Record not found", body = ErrorResponse),
            (status = 409, description = "Record conflict", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn delete_record(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<IdParams>,
    Query(preview): Query<DryRunQuery>,
) -> Result<Response, ApiError> {
    let response = RecordService::delete(&caller, params.id, preview.dry_run).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Delete every record matching the filter.
#[utoipa::path(
        delete,
        path = "/records",
        tag = "Record",
        summary = "Delete records by name",
        description = "Removes every record matching the filter in one transaction, so the zone advances by a single serial and sends one NOTIFY. Narrowing follows RFC 2136, Section 2.5.2: a name alone takes every type at it, adding type narrows to that type, adding value takes one record. Matching nothing is not an error — the zone already reads the way the request asked for, so nothing moves.",
        params(DeleteRecordsFilter),
        responses(
            (status = 200, description = "Records deleted", body = DeleteRecordsResponse),
            (status = 400, description = "Invalid filter", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "Forbidden", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn delete_records_matching(
    RequestCaller(caller): RequestCaller,
    Query(filter): Query<DeleteRecordsFilter>,
) -> Result<Response, ApiError> {
    let response = RecordService::delete_matching(&caller, &filter).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Bulk insert DNS records into a zone in a single transaction.
#[utoipa::path(
        post,
        path = "/records/bulk",
        tag = "Record",
        summary = "Bulk insert DNS records into a zone",
        description = "Insert many records into the named zone in one transaction. The zone serial is incremented once and a single NOTIFY is sent. Either all records are inserted or none are. With dry_run the same validation runs but nothing is applied.",
        request_body = CreateBulkRecordsRequest,
        responses(
            (status = 201, description = "DNS records created successfully", body = BulkRecordsResponse),
            (status = 200, description = "Dry run validated successfully, nothing applied", body = BulkRecordsResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The token's grants do not allow this record write", body = ErrorResponse),
            (status = 404, description = "Zone not found, or not visible to the token", body = ErrorResponse),
            (status = 409, description = "Record conflict", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn create_records_bulk(
    RequestCaller(caller): RequestCaller,
    JsonBody(body): JsonBody<CreateBulkRecordsRequest>,
) -> Result<Response, ApiError> {
    let response =
        RecordService::create_bulk(&caller, &body.zone_name, &body.records, body.dry_run).await?;

    // 201 says a resource now exists; a preview created nothing.
    let status = if response.applied {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(response)).into_response())
}
