//! HTTP export operations for managed zones.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use bindizr_service::types::{ErrorResponse, ZoneView};
use bindizr_service::{Context, zone};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::api::error::ApiError;
use crate::api::extract::{Path, Query, RequestCaller};
use crate::api::params::NameParams;

/// The view switch of a zone export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExportZoneQuery {
    /// Append the derived DNSSEC records.
    include_dnssec: Option<bool>,
}

/// Render a zone as a BIND zone file.
#[utoipa::path(
        get,
        path = "/zones/{name}/export",
        tag = "Zone",
        summary = "Export a zone as a BIND zone file",
        description = "Renders the zone and its records as an RFC 1035 master file, the inverse of the import endpoint. With `include_dnssec`, the derived DNSSEC records (DNSKEY, RRSIG, the denial chain, CDS/CDNSKEY) are appended in presentation form — an inspection artifact, not an import input.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone to export."),
            ExportZoneQuery
        ),
        responses(
            (status = 200, description = "The zone as a BIND zone file", content_type = "text/plain", body = String),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn export_zone(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
    Query(query): Query<ExportZoneQuery>,
) -> Result<Response, ApiError> {
    let zone_file = zone::export(
        &cx,
        &caller,
        &zone::normalize_name(&params.name)?,
        ZoneView::from_include_dnssec(query.include_dnssec.unwrap_or(false)),
    )
    .await?;

    Ok((
        StatusCode::OK,
        [(CONTENT_TYPE, "text/plain; charset=utf-8")],
        zone_file,
    )
        .into_response())
}
