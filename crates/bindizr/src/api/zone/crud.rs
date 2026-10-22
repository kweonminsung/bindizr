//! HTTP crud operations for managed zones.

use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bindizr_service::{
    Context,
    types::{
        CreateZoneRequest, DEFAULT_PAGE_LIMIT, DeleteZoneResponse, ErrorResponse,
        PaginatedResponse, Run, SingleZoneResponse, UpdateZoneRequest, WriteZoneResponse,
        ZoneFilter, ZoneResponse,
    },
    zone,
};

use crate::{
    api::{
        RequestCaller,
        error::{ApiError, Path, Query},
        middleware::body_parser::JsonBody,
        query::DryRunQuery,
    },
    params::NameParams,
};

/// List DNS zones, optionally filtered and paginated.
#[utoipa::path(
        get,
        path = "/zones",
        tag = "Zone",
        summary = "List all DNS zones",
        params(ZoneFilter),
        responses(
            (status = 200, description = "A list of DNS zones", body = PaginatedResponse<ZoneResponse>),
            (status = 400, description = "Bad request, invalid pagination", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_zones(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Query(mut filter): Query<ZoneFilter>,
) -> Result<Response, ApiError> {
    filter.limit = filter.limit.or(Some(DEFAULT_PAGE_LIMIT));
    let response = zone::list_by_filter(&cx, &caller, filter).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Get a single DNS zone.
#[utoipa::path(
        get,
        path = "/zones/{name}",
        tag = "Zone",
        summary = "Get a specific DNS zone",
        description = "Returns the zone's SOA metadata. For its records, list them with `GET /records?zone_name=`, or render the whole zone as a master file with `GET /zones/{name}/export`.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone to retrieve.")
        ),
        responses(
            (status = 200, description = "Details of the DNS zone", body = SingleZoneResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn get_zone(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
) -> Result<Response, ApiError> {
    let zone = zone::get_by_name(&cx, &caller, &zone::normalize_name(&params.name)?).await?;

    Ok((
        StatusCode::OK,
        Json(SingleZoneResponse {
            zone: ZoneResponse::from(&zone),
        }),
    )
        .into_response())
}

/// Create a new DNS zone.
#[utoipa::path(
        post,
        path = "/zones",
        tag = "Zone",
        summary = "Create a new DNS zone",
        request_body = CreateZoneRequest,
        responses(
            (status = 201, description = "DNS zone created successfully", body = WriteZoneResponse),
            (status = 200, description = "Dry run validated successfully, nothing applied", body = WriteZoneResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 409, description = "A zone with the same name already exists", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn create_zone(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    JsonBody(body): JsonBody<CreateZoneRequest>,
) -> Result<Response, ApiError> {
    let response = zone::create(&cx, &caller, &body).await?;

    // 201 says a resource now exists; a preview created nothing.
    let status = if response.applied {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };

    Ok((status, Json(response)).into_response())
}

/// Update an existing DNS zone.
#[utoipa::path(
        put,
        path = "/zones/{name}",
        tag = "Zone",
        summary = "Update a specific DNS zone",
        description = "Applies the given fields and keeps the rest; a different `name` renames the zone, which also needs `zone:create` in all zones. The serial advances by itself and cannot be set here.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone to update.")
        ),
        request_body = UpdateZoneRequest,
        responses(
            (status = 200, description = "DNS zone updated successfully", body = WriteZoneResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 409, description = "A zone with the new name already exists", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn update_zone(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
    JsonBody(body): JsonBody<UpdateZoneRequest>,
) -> Result<Response, ApiError> {
    let response = zone::update(&cx, &caller, &zone::normalize_name(&params.name)?, &body).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Delete a DNS zone.
#[utoipa::path(
        delete,
        path = "/zones/{name}",
        tag = "Zone",
        summary = "Delete a specific DNS zone",
        description = "Deletes the zone with its records and saved versions, and answers with what went. With `dry_run=true` the counts are reported and nothing is removed.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone to delete."),
            DryRunQuery
        ),
        responses(
            (status = 200, description = "DNS zone deleted successfully", body = DeleteZoneResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn delete_zone(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
    Query(query): Query<DryRunQuery>,
) -> Result<Response, ApiError> {
    let response = zone::delete(
        &cx,
        &caller,
        &zone::normalize_name(&params.name)?,
        Run::from_dry_run(query.dry_run),
    )
    .await?;

    Ok((StatusCode::OK, Json(response)).into_response())
}
