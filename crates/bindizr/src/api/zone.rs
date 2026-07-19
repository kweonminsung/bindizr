use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query},
    http::StatusCode,
    response::IntoResponse,
    routing,
};
use bindizr_service::{record::RecordService, zone::ZoneService};
use serde::Deserialize;
use serde_json::json;

use crate::api::{
    error::ApiError,
    middleware::body_parser::{JsonBody, MAX_UPLOAD_BODY_BYTES},
    types::{
        CreateZoneRequest, ErrorResponse, GetRecordResponse, GetZoneResponse, GetZonesFilter,
        ImportZoneFileRequest, ImportZoneFileResponse, MessageResponse, ZoneDetailResponse,
        ZoneListResponse, ZoneResponse,
    },
};

/// Route group for zone endpoints.
pub(crate) struct ZoneApi;

impl ZoneApi {
    /// Build the router for zone endpoints.
    pub(crate) async fn routes() -> Router {
        Router::new()
            .route("/zones", routing::get(get_zones))
            .route("/zones/{name}", routing::get(get_zone))
            .route("/zones", routing::post(create_zone))
            .route("/zones/{name}", routing::put(update_zone))
            .route("/zones/{name}", routing::delete(delete_zone))
            .route(
                "/zones/{name}/imports",
                routing::post(import_zone).layer(DefaultBodyLimit::max(MAX_UPLOAD_BODY_BYTES)),
            )
    }
}

#[utoipa::path(
        get,
        path = "/zones",
        tag = "Zone",
        summary = "List all DNS zones",
        params(
            ("name" = Option<String>, Query, description = "Filter by zone name."),
            ("id" = Option<i32>, Query, description = "Filter by zone ID."),
            ("primary_ns" = Option<String>, Query, description = "Filter by primary name server."),
            ("admin_email" = Option<String>, Query, description = "Filter by admin email."),
            ("ttl" = Option<i32>, Query, description = "Filter by TTL."),
            ("min_ttl" = Option<i32>, Query, description = "Filter by minimum TTL."),
            ("max_ttl" = Option<i32>, Query, description = "Filter by maximum TTL."),
            ("serial" = Option<i32>, Query, description = "Filter by serial."),
            ("search" = Option<String>, Query, description = "Partially search zones."),
            ("limit" = Option<u32>, Query, description = "Maximum number of zones to return."),
            ("offset" = Option<u64>, Query, description = "Number of zones to skip.")
        ),
        responses(
            (status = 200, description = "A list of DNS zones", body = ZoneListResponse),
            (status = 400, description = "Bad request, invalid pagination", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// List DNS zones, optionally filtered and paginated.
pub(crate) async fn get_zones(Query(query): Query<GetZonesFilter>) -> impl IntoResponse {
    match ZoneService::list_by_filter(query).await {
        Ok(response) => {
            let zones = response
                .items
                .iter()
                .map(GetZoneResponse::from_zone)
                .collect::<Vec<GetZoneResponse>>();
            let json_body = json!({ "items": zones, "pagination": response.pagination });
            (StatusCode::OK, Json(json_body)).into_response()
        }
        Err(err) => ApiError::from(err).into_response(),
    }
}

#[utoipa::path(
        get,
        path = "/zones/{name}",
        tag = "Zone",
        summary = "Get a specific DNS zone",
        params(
            ("name" = String, Path, description = "The name of the DNS zone to retrieve."),
            ("records" = Option<bool>, Query, description = "Whether to include records for the DNS zone.")
        ),
        responses(
            (status = 200, description = "Details of the DNS zone", body = ZoneDetailResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Get a single DNS zone, optionally including its records.
pub(crate) async fn get_zone(
    Path(params): Path<GetZoneParam>,
    Query(query): Query<GetZoneQuery>,
) -> impl IntoResponse {
    let zone_name = params.name;
    let records_query = query.records;

    let raw_zone = match ZoneService::get_by_name(&zone_name).await {
        Ok(zone) => zone,
        Err(err) => return ApiError::from(err).into_response(),
    };

    let raw_records = match records_query {
        Some(true) => match RecordService::list(Some(raw_zone.name.clone())).await {
            Ok(records) => records,
            Err(err) => return ApiError::from(err).into_response(),
        },
        _ => vec![],
    };
    let records = raw_records
        .iter()
        .map(|record| GetRecordResponse::from_record_and_zone_name(record, &raw_zone.name))
        .collect::<Vec<GetRecordResponse>>();

    let zone = GetZoneResponse::from_zone(&raw_zone);
    let json_body = json!({ "zone": zone, "records": records });
    (StatusCode::OK, Json(json_body)).into_response()
}

#[utoipa::path(
        post,
        path = "/zones",
        tag = "Zone",
        summary = "Create a new DNS zone",
        request_body = CreateZoneRequest,
        responses(
            (status = 201, description = "DNS zone created successfully", body = ZoneResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Create a new DNS zone.
pub(crate) async fn create_zone(JsonBody(body): JsonBody<CreateZoneRequest>) -> impl IntoResponse {
    match ZoneService::create(&body).await {
        Ok(zone) => {
            let zone = GetZoneResponse::from_zone(&zone);
            let json_body = json!({ "zone": zone });
            (StatusCode::CREATED, Json(json_body)).into_response()
        }
        Err(err) => ApiError::from(err).into_response(),
    }
}

#[utoipa::path(
        put,
        path = "/zones/{name}",
        tag = "Zone",
        summary = "Update a specific DNS zone",
        params(
            ("name" = String, Path, description = "The name of the DNS zone to update.")
        ),
        request_body = CreateZoneRequest,
        responses(
            (status = 200, description = "DNS zone updated successfully", body = ZoneResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Update an existing DNS zone.
pub(crate) async fn update_zone(
    Path(params): Path<UpdateZoneParam>,
    JsonBody(body): JsonBody<CreateZoneRequest>,
) -> impl IntoResponse {
    let zone_name = params.name;

    match ZoneService::update(&zone_name, &body).await {
        Ok(zone) => {
            let zone = GetZoneResponse::from_zone(&zone);
            let json_body = json!({ "zone": zone });
            (StatusCode::OK, Json(json_body)).into_response()
        }
        Err(err) => ApiError::from(err).into_response(),
    }
}

#[utoipa::path(
        delete,
        path = "/zones/{name}",
        tag = "Zone",
        summary = "Delete a specific DNS zone",
        params(
            ("name" = String, Path, description = "The name of the DNS zone to delete.")
        ),
        responses(
            (status = 200, description = "DNS zone deleted successfully", body = MessageResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Delete a DNS zone.
pub(crate) async fn delete_zone(Path(params): Path<DeleteZoneParam>) -> impl IntoResponse {
    let zone_name = params.name;

    match ZoneService::delete(&zone_name).await {
        Ok(_) => {
            let json_body = json!({ "message": "Zone deleted successfully" });
            (StatusCode::OK, Json(json_body)).into_response()
        }
        Err(err) => ApiError::from(err).into_response(),
    }
}

#[utoipa::path(
        post,
        path = "/zones/{name}/imports",
        tag = "Zone",
        summary = "Import a BIND zone file into a zone",
        description = "Parse BIND zone file text and reconcile it with the zone using append/upsert/replace. When applied, the zone serial is incremented once and a single NOTIFY is sent. If any record fails validation nothing is applied and the errors are returned.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone to import records into.")
        ),
        request_body = ImportZoneFileRequest,
        responses(
            (status = 200, description = "Import summary and validation errors", body = ImportZoneFileResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Import a BIND zone file into a zone, reconciling records in one transaction.
pub(crate) async fn import_zone(
    Path(params): Path<ImportZoneParam>,
    JsonBody(body): JsonBody<ImportZoneFileRequest>,
) -> impl IntoResponse {
    match RecordService::import_zone_file(&params.name, &body).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => ApiError::from(err).into_response(),
    }
}

/// Path parameters for importing a zone file.
#[derive(Debug, Deserialize)]
pub(crate) struct ImportZoneParam {
    name: String,
}

/// Path parameters for fetching a zone.
#[derive(Debug, Deserialize)]
pub(crate) struct GetZoneParam {
    name: String,
}

/// Query parameters for fetching a zone.
#[derive(Debug, Deserialize)]
pub(crate) struct GetZoneQuery {
    records: Option<bool>,
}

/// Path parameters for updating a zone.
#[derive(Debug, Deserialize)]
pub(crate) struct UpdateZoneParam {
    name: String,
}

/// Path parameters for deleting a zone.
#[derive(Debug, Deserialize)]
pub(crate) struct DeleteZoneParam {
    name: String,
}
