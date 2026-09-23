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
        CreateZoneRequest, DEFAULT_PAGE_LIMIT, DeleteZoneResponse, ErrorResponse, GetZoneResponse,
        GetZonesFilter, ImportZoneRequest, ImportZoneResponse, PaginatedResponse,
        RollbackZoneResponse, UpdateZoneRequest, VersionDetailResponse, VersionDiffResponse,
        ZoneResponse, ZoneStatusResponse, ZoneVersionResponse, ZoneWriteResponse,
    },
    zone::ZoneService,
};
use serde::Deserialize;

use crate::api::{
    DryRunQuery, RequestCaller, ZoneNameParam,
    error::{ApiError, Path, Query},
    middleware::body_parser::{JsonBody, MAX_UPLOAD_BODY_BYTES},
};

pub(crate) struct ZoneApi;

impl ZoneApi {
    /// Build the zone API routes.
    pub(crate) async fn routes() -> Router {
        Router::new()
            .route("/zones", routing::get(list_zones))
            .route("/zones/{name}", routing::get(get_zone))
            .route("/zones", routing::post(create_zone))
            .route("/zones/{name}", routing::put(update_zone))
            .route("/zones/{name}", routing::delete(delete_zone))
            .route(
                "/zones/{name}/import",
                routing::post(import_zone).layer(DefaultBodyLimit::max(MAX_UPLOAD_BODY_BYTES)),
            )
            .route("/zones/{name}/export", routing::get(export_zone))
            .route("/zones/{name}/versions", routing::get(list_zone_versions))
            .route(
                "/zones/{name}/versions/diff",
                routing::get(diff_zone_versions),
            )
            .route(
                "/zones/{name}/versions/{serial}",
                routing::get(get_zone_version),
            )
            .route(
                "/zones/{name}/versions/{serial}/rollback",
                routing::post(rollback_zone),
            )
            .route("/zones/{name}/status", routing::get(get_zone_status))
    }
}

/// Report the sync state of every enabled secondary for a zone.
#[utoipa::path(
        get,
        path = "/zones/{name}/status",
        tag = "Zone",
        summary = "Check how far each secondary has caught up with a zone",
        description = "Queries every enabled secondary for the SOA serial it currently serves and compares it with the zone's serial. Probes run live and in parallel; an unreachable secondary is reported with the failure reason. With no enabled secondaries the list is empty.",
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
pub(crate) async fn get_zone_status(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
) -> Result<Response, ApiError> {
    let status = ZoneService::get_status(&caller, &params.name).await?;
    Ok((StatusCode::OK, Json(status)).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExportZoneQuery {
    signed: Option<bool>,
}

/// Render a zone as BIND master-file text.
#[utoipa::path(
        get,
        path = "/zones/{name}/export",
        tag = "Zone",
        summary = "Export a zone as BIND master-file text",
        description = "Renders the zone and its records as an RFC 1035 master file, the inverse of the import endpoint. With `signed`, the derived DNSSEC records (DNSKEY, RRSIG, the denial chain, CDS/CDNSKEY) are appended in presentation form — an inspection artifact, not an import input.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone to export."),
            ("signed" = Option<bool>, Query, description = "Append the derived DNSSEC records.")
        ),
        responses(
            (status = 200, description = "The zone as master-file text", content_type = "text/plain", body = String),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn export_zone(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    Query(query): Query<ExportZoneQuery>,
) -> Result<Response, ApiError> {
    let zone_file =
        ZoneService::export(&caller, &params.name, query.signed.unwrap_or(false)).await?;
    Ok((
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        zone_file,
    )
        .into_response())
}

/// List a zone's versions, newest serial first.
#[utoipa::path(
        get,
        path = "/zones/{name}/versions",
        tag = "Zone",
        summary = "List a zone's versions (serial history)",
        description = "Every zone mutation records a version of the zone's SOA metadata keyed by serial. Versions are returned newest serial first.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone."),
            ("limit" = Option<u32>, Query, minimum = 1, maximum = 1000, description = "Versions per page; defaults to 50."),
            ("offset" = Option<u64>, Query, description = "Number of versions to skip."),
            ("include_signer_serials" = Option<bool>, Query, description = "Include signer-only serials (DNSSEC re-signs and rollovers); by default only serials with user changes, plus the current serial, are listed.")
        ),
        responses(
            (status = 200, description = "A list of zone versions", body = PaginatedResponse<ZoneVersionResponse>),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_zone_versions(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    Query(query): Query<VersionListQuery>,
) -> Result<Response, ApiError> {
    let response = ZoneService::list_versions(
        &caller,
        &params.name,
        query.limit.or(Some(DEFAULT_PAGE_LIMIT)),
        query.offset,
        query.include_signer_serials,
    )
    .await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Get one version plus the reconstructed records at that serial.
#[utoipa::path(
        get,
        path = "/zones/{name}/versions/{serial}",
        tag = "Zone",
        summary = "Get the zone state captured at a version serial",
        description = "Returns the version's SOA fields together with the zone's records at that serial, reconstructed from the journal.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone."),
            ("serial" = i32, Path, description = "The version serial to inspect.")
        ),
        responses(
            (status = 200, description = "The version and its reconstructed records", body = VersionDetailResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone or version not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn get_zone_version(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneVersionParam>,
) -> Result<Response, ApiError> {
    let response = ZoneService::get_version(&caller, &params.name, params.serial).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Roll a zone back to the state captured at a version serial.
#[utoipa::path(
        post,
        path = "/zones/{name}/versions/{serial}/rollback",
        tag = "Zone",
        summary = "Roll a zone back to a version serial",
        description = "Restores the zone's records and SOA metadata to the state captured at the target serial. The zone serial still advances to a new value (serials never go backward) and a single NOTIFY is sent. The zone name is not part of a version and is never changed. With `dry_run=true` the rollback is computed and reported without applying any change.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone to roll back."),
            ("serial" = i32, Path, description = "The version serial to roll back to."),
            ("dry_run" = Option<bool>, Query, description = "Compute and report the rollback without applying it.")
        ),
        responses(
            (status = 200, description = "Rollback result", body = RollbackZoneResponse),
            (status = 400, description = "Bad request, invalid target serial", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone or version not found", body = ErrorResponse),
            (status = 409, description = "Record conflict", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn rollback_zone(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneVersionParam>,
    Query(query): Query<DryRunQuery>,
) -> Result<Response, ApiError> {
    let response =
        ZoneService::rollback(&caller, &params.name, params.serial, query.dry_run).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VersionListQuery {
    limit: Option<u32>,
    #[serde(default)]
    include_signer_serials: bool,
    offset: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ZoneVersionParam {
    name: String,
    serial: i32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VersionDiffQuery {
    from: i32,
    to: Option<i32>,
}

/// Diff the records at two of a zone's serials.
#[utoipa::path(
        get,
        path = "/zones/{name}/versions/diff",
        tag = "Zone",
        summary = "Diff the records between two of a zone's serials",
        description = "Reports the records added, removed, and changed between `from` and `to`, grouped by name and type. Omitting `to` compares against the current serial. Each serial must be the current one or an existing version.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone."),
            ("from" = i32, Query, description = "The serial to diff from."),
            ("to" = Option<i32>, Query, description = "The serial to diff to; defaults to the current serial.")
        ),
        responses(
            (status = 200, description = "The record differences between the two serials", body = VersionDiffResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone or version not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn diff_zone_versions(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    Query(query): Query<VersionDiffQuery>,
) -> Result<Response, ApiError> {
    let diff = ZoneService::diff_versions(&caller, &params.name, query.from, query.to).await?;
    Ok((StatusCode::OK, Json(diff)).into_response())
}

/// List DNS zones, optionally filtered and paginated.
#[utoipa::path(
        get,
        path = "/zones",
        tag = "Zone",
        summary = "List all DNS zones",
        params(
            ("name" = Option<String>, Query, description = "Filter by zone name."),
            ("id" = Option<i32>, Query, description = "Filter by zone ID."),
            ("mname" = Option<String>, Query, description = "Filter by mname."),
            ("rname" = Option<String>, Query, description = "Filter by rname."),
            ("default_ttl" = Option<i32>, Query, description = "Filter by default TTL."),
            ("min_default_ttl" = Option<i32>, Query, description = "Filter by minimum default TTL."),
            ("max_default_ttl" = Option<i32>, Query, description = "Filter by maximum default TTL."),
            ("serial" = Option<i32>, Query, description = "Filter by serial."),
            ("min_serial" = Option<i32>, Query, description = "Filter by minimum serial."),
            ("max_serial" = Option<i32>, Query, description = "Filter by maximum serial."),
            ("created_after" = Option<String>, Query, description = "Keep zones created at or after this RFC 3339 timestamp."),
            ("created_before" = Option<String>, Query, description = "Keep zones created at or before this RFC 3339 timestamp."),
            ("signed" = Option<bool>, Query, description = "true keeps the zones signing under a DNSSEC policy, false the rest."),
            ("enabled" = Option<bool>, Query, description = "true keeps the zones the DNS plane serves, false the disabled ones."),
            ("search" = Option<String>, Query, description = "Partially search zones."),
            ("sort" = Option<String>, Query, description = "Sort by name (the default), serial, default_ttl, or created_at."),
            ("order" = Option<String>, Query, description = "asc (the default) or desc."),
            ("limit" = Option<u32>, Query, minimum = 1, maximum = 1000, description = "Zones per page; defaults to 50."),
            ("offset" = Option<u64>, Query, description = "Number of zones to skip.")
        ),
        responses(
            (status = 200, description = "A list of DNS zones", body = PaginatedResponse<GetZoneResponse>),
            (status = 400, description = "Bad request, invalid pagination", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_zones(
    RequestCaller(caller): RequestCaller,
    Query(mut query): Query<GetZonesFilter>,
) -> Result<Response, ApiError> {
    query.limit = query.limit.or(Some(DEFAULT_PAGE_LIMIT));
    let response = ZoneService::list_by_filter(&caller, query).await?;
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
            (status = 200, description = "Details of the DNS zone", body = ZoneResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn get_zone(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
) -> Result<Response, ApiError> {
    let zone = ZoneService::get_by_name(&caller, &params.name).await?;
    Ok((
        StatusCode::OK,
        Json(ZoneResponse {
            zone: GetZoneResponse::from_zone(&zone),
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
            (status = 201, description = "DNS zone created successfully", body = ZoneWriteResponse),
            (status = 200, description = "Dry run validated successfully, nothing applied", body = ZoneWriteResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 409, description = "A zone with the same name already exists", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn create_zone(
    RequestCaller(caller): RequestCaller,
    JsonBody(body): JsonBody<CreateZoneRequest>,
) -> Result<Response, ApiError> {
    let response = ZoneService::create(&caller, &body).await?;
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
        description = "Applies the given fields and keeps the rest; a different `name` renames the zone. The serial advances by itself and cannot be set here.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone to update.")
        ),
        request_body = UpdateZoneRequest,
        responses(
            (status = 200, description = "DNS zone updated successfully", body = ZoneWriteResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 409, description = "A zone with the new name already exists", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn update_zone(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    JsonBody(body): JsonBody<UpdateZoneRequest>,
) -> Result<Response, ApiError> {
    let response = ZoneService::update(&caller, &params.name, &body).await?;
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
            ("dry_run" = Option<bool>, Query, description = "Report what would go without removing it.")
        ),
        responses(
            (status = 200, description = "DNS zone deleted successfully", body = DeleteZoneResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn delete_zone(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    Query(preview): Query<DryRunQuery>,
) -> Result<Response, ApiError> {
    let response = ZoneService::delete(&caller, &params.name, preview.dry_run).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Import records into a zone, reconciling them in one transaction.
#[utoipa::path(
        post,
        path = "/zones/{name}/import",
        tag = "Zone",
        summary = "Import records into a zone",
        description = "Reconcile records with the zone using append/upsert/replace, taken from BIND zone file text in `content` or transferred over AXFR from `from_server` (exactly one of the two; the source must allow the transfer). When applied, the zone serial is incremented once and a single NOTIFY is sent. If any record fails validation nothing is applied and the answer is 422, carrying the per-record errors. A record type bindizr does not store fails the file the same way unless `skip_unsupported` is set, which passes over those records and lists them in `skipped_records`. TTLs are decimal seconds as RFC 1035 defines them; a file using BIND's unit suffixes (`1h`) is refused — write it out in seconds first with `named-compilezone -o - <zone> <file>`.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone to import records into.")
        ),
        request_body = ImportZoneRequest,
        responses(
            (status = 200, description = "Import summary", body = ImportZoneResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 409, description = "Record conflict", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 422, description = "The file was rejected and nothing was applied; the same body carries the per-record errors", body = ImportZoneResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn import_zone(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    JsonBody(body): JsonBody<ImportZoneRequest>,
) -> Result<Response, ApiError> {
    let response = RecordService::import_zone(&caller, &params.name, &body).await?;
    // A rejected file is a failed request, so a generic client does not read it
    // as an import; the body stays the same so the errors survive the status.
    let status = if response.was_rejected() {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::OK
    };
    Ok((status, Json(response)).into_response())
}
