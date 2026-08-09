use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_dns as dns;
use bindizr_service::{
    record::RecordService,
    types::{
        CreateZoneRequest, ErrorResponse, GetRecordResponse, GetZoneResponse, GetZonesFilter,
        ImportZoneFileRequest, ImportZoneFileResponse, MessageResponse, PaginatedResponse,
        RollbackZoneRequest, RollbackZoneResponse, SnapshotDetailResponse, SnapshotDiffResponse,
        SnapshotRecordResponse, ZoneDetailResponse, ZoneResponse, ZoneSnapshotResponse,
        ZoneStatusResponse,
    },
    zone::ZoneService,
};
use serde::Deserialize;
use serde_json::json;

use crate::api::{
    RequestCaller,
    error::ApiError,
    middleware::body_parser::{JsonBody, MAX_UPLOAD_BODY_BYTES},
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
            .route("/zones/{name}/export", routing::get(export_zone))
            .route("/zones/{name}/snapshots", routing::get(list_zone_snapshots))
            .route(
                "/zones/{name}/snapshots/diff",
                routing::get(diff_zone_snapshots),
            )
            .route(
                "/zones/{name}/snapshots/{serial}",
                routing::get(get_zone_snapshot),
            )
            .route("/zones/{name}/rollback", routing::post(rollback_zone))
            .route("/zones/{name}/status", routing::get(get_zone_status))
    }
}

#[utoipa::path(
        get,
        path = "/zones/{name}/status",
        tag = "Zone",
        summary = "Check how far each secondary has caught up with a zone",
        description = "Queries every configured secondary for the SOA serial it currently serves and compares it with the zone's serial. Probes run live and in parallel; an unreachable secondary is reported with the failure reason. With no secondaries configured the list is empty.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        responses(
            (status = 200, description = "The zone's secondary sync status", body = ZoneStatusResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Report the sync state of every configured secondary for a zone.
pub(crate) async fn get_zone_status(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
) -> Result<Response, ApiError> {
    let status = dns::status::zone_status(&caller, &params.name).await?;
    Ok((StatusCode::OK, Json(status)).into_response())
}

#[utoipa::path(
        get,
        path = "/zones/{name}/export",
        tag = "Zone",
        summary = "Export a zone as BIND master-file text",
        description = "Renders the zone and its records as an RFC 1035 master file, the inverse of the import endpoint.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone to export.")
        ),
        responses(
            (status = 200, description = "The zone as master-file text", content_type = "text/plain", body = String),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Render a zone as BIND master-file text.
pub(crate) async fn export_zone(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
) -> Result<Response, ApiError> {
    let zone_file = ZoneService::export_zone_file_for(&caller, &params.name).await?;
    Ok((
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        zone_file,
    )
        .into_response())
}

#[utoipa::path(
        get,
        path = "/zones/{name}/snapshots",
        tag = "Zone",
        summary = "List a zone's snapshots (serial history)",
        description = "Every zone mutation records a snapshot of the zone's SOA metadata keyed by serial. Snapshots are returned newest serial first.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone."),
            ("limit" = Option<u32>, Query, description = "Maximum number of snapshots to return."),
            ("offset" = Option<u64>, Query, description = "Number of snapshots to skip.")
        ),
        responses(
            (status = 200, description = "A list of zone snapshots", body = PaginatedResponse<ZoneSnapshotResponse>),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// List a zone's snapshots, newest serial first.
pub(crate) async fn list_zone_snapshots(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    Query(query): Query<SnapshotListQuery>,
) -> Result<Response, ApiError> {
    let response =
        ZoneService::list_snapshots_for(&caller, &params.name, query.limit, query.offset).await?;
    let mut items = Vec::with_capacity(response.items.len());
    for snapshot in &response.items {
        items.push(ZoneSnapshotResponse::from_snapshot(snapshot)?);
    }
    let json_body = json!({ "items": items, "pagination": response.pagination });
    Ok((StatusCode::OK, Json(json_body)).into_response())
}

#[utoipa::path(
        get,
        path = "/zones/{name}/snapshots/{serial}",
        tag = "Zone",
        summary = "Get the zone state captured at a snapshot serial",
        description = "Returns the SOA snapshot at the given serial together with the zone's record set at that serial, reconstructed from the change history.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone."),
            ("serial" = i32, Path, description = "The snapshot serial to inspect.")
        ),
        responses(
            (status = 200, description = "The snapshot and its reconstructed records", body = SnapshotDetailResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone or snapshot not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Get one snapshot plus the reconstructed record set at that serial.
pub(crate) async fn get_zone_snapshot(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneSnapshotParam>,
) -> Result<Response, ApiError> {
    let (snapshot, records) =
        ZoneService::get_snapshot_for(&caller, &params.name, params.serial).await?;
    let snapshot = ZoneSnapshotResponse::from_snapshot(&snapshot)?;
    let records = records
        .into_iter()
        .map(SnapshotRecordResponse::from)
        .collect::<Vec<_>>();
    let response = SnapshotDetailResponse { snapshot, records };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[utoipa::path(
        post,
        path = "/zones/{name}/rollback",
        tag = "Zone",
        summary = "Roll a zone back to a snapshot serial",
        description = "Restores the zone's record set and SOA metadata to the state captured at the target serial. The zone serial still advances to a new value (serials never go backward) and a single NOTIFY is sent. The zone name is not part of a snapshot and is never changed. With dry_run the rollback is computed and reported without applying any change.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone to roll back.")
        ),
        request_body = RollbackZoneRequest,
        responses(
            (status = 200, description = "Rollback result", body = RollbackZoneResponse),
            (status = 400, description = "Bad request, invalid target serial", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone or snapshot not found", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Roll a zone back to the state captured at a snapshot serial.
pub(crate) async fn rollback_zone(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    JsonBody(body): JsonBody<RollbackZoneRequest>,
) -> Result<Response, ApiError> {
    caller.require_global("roll back zones")?;

    let response = ZoneService::rollback(&params.name, body.serial, body.dry_run).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Query parameters for listing zone snapshots.
#[derive(Debug, Deserialize)]
pub(crate) struct SnapshotListQuery {
    limit: Option<u32>,
    offset: Option<u64>,
}

/// Path parameters addressing a zone snapshot by zone name and serial.
#[derive(Debug, Deserialize)]
pub(crate) struct ZoneSnapshotParam {
    name: String,
    serial: i32,
}

/// Query parameters selecting the two serials to diff.
#[derive(Debug, Deserialize)]
pub(crate) struct SnapshotDiffQuery {
    from: i32,
    to: Option<i32>,
}

#[utoipa::path(
        get,
        path = "/zones/{name}/snapshots/diff",
        tag = "Zone",
        summary = "Diff the records between two of a zone's serials",
        description = "Reports the RRsets added, removed, and changed between `from` and `to`. Omitting `to` compares against the current serial. Each serial must be the current one or an existing snapshot.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone."),
            ("from" = i32, Query, description = "The serial to diff from."),
            ("to" = Option<i32>, Query, description = "The serial to diff to; defaults to the current serial.")
        ),
        responses(
            (status = 200, description = "The record differences between the two serials", body = SnapshotDiffResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone or snapshot not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Diff the record sets at two of a zone's serials.
pub(crate) async fn diff_zone_snapshots(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    Query(query): Query<SnapshotDiffQuery>,
) -> Result<Response, ApiError> {
    let diff = ZoneService::diff_snapshots_for(&caller, &params.name, query.from, query.to).await?;
    Ok((StatusCode::OK, Json(diff)).into_response())
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
            (status = 200, description = "A list of DNS zones", body = PaginatedResponse<GetZoneResponse>),
            (status = 400, description = "Bad request, invalid pagination", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// List DNS zones, optionally filtered and paginated.
pub(crate) async fn get_zones(
    RequestCaller(caller): RequestCaller,
    Query(query): Query<GetZonesFilter>,
) -> Result<Response, ApiError> {
    let response = ZoneService::list_by_filter_for(&caller, query).await?;
    let zones = response
        .items
        .iter()
        .map(GetZoneResponse::from_zone)
        .collect::<Vec<GetZoneResponse>>();
    let json_body = json!({ "items": zones, "pagination": response.pagination });
    Ok((StatusCode::OK, Json(json_body)).into_response())
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
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    Query(query): Query<GetZoneQuery>,
) -> Result<Response, ApiError> {
    let raw_zone = ZoneService::get_by_name_for(&caller, &params.name).await?;

    let raw_records = match query.records {
        Some(true) => RecordService::list(Some(raw_zone.name.clone())).await?,
        _ => vec![],
    };
    let records = raw_records
        .iter()
        .map(|record| GetRecordResponse::from_record_and_zone_name(record, &raw_zone.name))
        .collect::<Vec<GetRecordResponse>>();

    let zone = GetZoneResponse::from_zone(&raw_zone);
    let json_body = json!({ "zone": zone, "records": records });
    Ok((StatusCode::OK, Json(json_body)).into_response())
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
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Create a new DNS zone.
pub(crate) async fn create_zone(
    RequestCaller(caller): RequestCaller,
    JsonBody(body): JsonBody<CreateZoneRequest>,
) -> Result<Response, ApiError> {
    caller.require_global("create zones")?;

    let zone = ZoneService::create(&body).await?;
    let zone = GetZoneResponse::from_zone(&zone);
    let json_body = json!({ "zone": zone });
    Ok((StatusCode::CREATED, Json(json_body)).into_response())
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
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Update an existing DNS zone.
pub(crate) async fn update_zone(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    JsonBody(body): JsonBody<CreateZoneRequest>,
) -> Result<Response, ApiError> {
    caller.require_global("update zones")?;

    let zone = ZoneService::update(&params.name, &body).await?;
    let zone = GetZoneResponse::from_zone(&zone);
    let json_body = json!({ "zone": zone });
    Ok((StatusCode::OK, Json(json_body)).into_response())
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
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Delete a DNS zone.
pub(crate) async fn delete_zone(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
) -> Result<Response, ApiError> {
    caller.require_global("delete zones")?;

    ZoneService::delete(&params.name).await?;
    let json_body = json!({ "message": "Zone deleted successfully" });
    Ok((StatusCode::OK, Json(json_body)).into_response())
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
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Import a BIND zone file into a zone, reconciling records in one transaction.
pub(crate) async fn import_zone(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    JsonBody(body): JsonBody<ImportZoneFileRequest>,
) -> Result<Response, ApiError> {
    caller.require_global("import zone files")?;

    let response = RecordService::import_zone_file(&params.name, &body).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Path parameters addressing a zone by name.
#[derive(Debug, Deserialize)]
pub(crate) struct ZoneNameParam {
    name: String,
}

/// Query parameters for fetching a zone.
#[derive(Debug, Deserialize)]
pub(crate) struct GetZoneQuery {
    records: Option<bool>,
}
