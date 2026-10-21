//! HTTP history operations for managed zones.

use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bindizr_core::{dns::Serial, model::zone_version::VersionFilter};
use bindizr_service::{
    Context,
    types::{
        DEFAULT_PAGE_LIMIT, DiffZoneVersionsResponse, ErrorResponse, GetZoneVersionResponse,
        PaginatedResponse, RollbackZoneResponse, Run, ZoneVersionResponse,
    },
    zone,
};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::{
    api::{
        RequestCaller,
        error::{ApiError, Path, Query},
        query::DryRunQuery,
    },
    params::NameParams,
};

/// List a zone's versions, newest serial first.
#[utoipa::path(
        get,
        path = "/zones/{name}/versions",
        tag = "Zone",
        summary = "List a zone's versions (serial history)",
        description = "Every zone mutation records a version of the zone's SOA metadata keyed by serial. Versions are returned newest serial first.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone."),
            ListZoneVersionsQuery
        ),
        responses(
            (status = 200, description = "A list of zone versions", body = PaginatedResponse<ZoneVersionResponse>),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_zone_versions(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
    Query(query): Query<ListZoneVersionsQuery>,
) -> Result<Response, ApiError> {
    let response = zone::list_versions(
        &cx,
        &caller,
        &zone::normalize_name(&params.name)?,
        query.limit.or(Some(DEFAULT_PAGE_LIMIT)),
        query.offset,
        VersionFilter::from_include_signer_serials(query.include_signer_serials),
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
            ("serial" = inline(Serial), Path, description = "The version serial to inspect.")
        ),
        responses(
            (status = 200, description = "The version and its reconstructed records", body = GetZoneVersionResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone or version not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn get_zone_version(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneVersionParams>,
) -> Result<Response, ApiError> {
    let response = zone::get_version(
        &cx,
        &caller,
        &zone::normalize_name(&params.name)?,
        params.serial,
    )
    .await?;

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Roll a zone back to the state captured at a version serial.
#[utoipa::path(
        post,
        path = "/zones/{name}/versions/{serial}/rollback",
        tag = "Zone",
        summary = "Roll a zone back to a version serial",
        description = "Restores the zone's records and SOA metadata to the state captured at the target serial. The zone serial still advances to a new value (serials never go backward) and a single NOTIFY is sent. The zone name is not part of a version and is never changed. It needs `zone:update`, and `record:read`, `record:create` and `record:delete` with no name or type narrowing, since it reads the version it restores. With `dry_run=true` the rollback is computed and reported without applying any change.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone to roll back."),
            ("serial" = inline(Serial), Path, description = "The version serial to roll back to."),
            DryRunQuery
        ),
        responses(
            (status = 200, description = "Rollback result", body = RollbackZoneResponse),
            (status = 400, description = "Bad request, invalid target serial", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "Zone or version not found", body = ErrorResponse),
            (status = 409, description = "Record conflict", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn rollback_zone(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneVersionParams>,
    Query(query): Query<DryRunQuery>,
) -> Result<Response, ApiError> {
    let response = zone::rollback(
        &cx,
        &caller,
        &zone::normalize_name(&params.name)?,
        params.serial,
        Run::from_dry_run(query.dry_run),
    )
    .await?;

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// The page and content filter of a version listing.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListZoneVersionsQuery {
    /// Versions per page; defaults to 50.
    #[param(minimum = 1, maximum = 1000)]
    limit: Option<u32>,
    /// Number of versions to skip.
    offset: Option<u64>,
    /// Include past serials with only derived DNSSEC changes. By default these are hidden; the current serial and serials without journal entries remain visible.
    #[serde(default)]
    include_signer_serials: bool,
}

/// One of a zone's versions, by name and serial.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct ZoneVersionParams {
    name: String,
    serial: Serial,
}

/// The two serials of a version diff.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiffZoneVersionsQuery {
    /// The serial to diff from.
    #[param(inline)]
    from: Serial,
    /// The serial to diff to; defaults to the current serial.
    #[param(inline)]
    to: Option<Serial>,
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
            DiffZoneVersionsQuery
        ),
        responses(
            (status = 200, description = "The record differences between the two serials", body = DiffZoneVersionsResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone or version not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn diff_zone_versions(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
    Query(query): Query<DiffZoneVersionsQuery>,
) -> Result<Response, ApiError> {
    let diff = zone::diff_versions(
        &cx,
        &caller,
        &zone::normalize_name(&params.name)?,
        query.from,
        query.to,
    )
    .await?;

    Ok((StatusCode::OK, Json(diff)).into_response())
}
