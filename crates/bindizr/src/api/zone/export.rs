//! HTTP export operations for managed zones.

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bindizr_service::{
    Context,
    types::{ErrorResponse, ZoneView},
    zone,
};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::{
    api::{
        RequestCaller,
        error::{ApiError, Path, Query},
    },
    params::NameParams,
};

/// Render a zone as BIND master-file text.
#[utoipa::path(
        get,
        path = "/zones/{name}/export",
        tag = "Zone",
        summary = "Export a zone as BIND master-file text",
        description = "Renders the zone and its records as an RFC 1035 master file, the inverse of the import endpoint. With `signed`, the derived DNSSEC records (DNSKEY, RRSIG, the denial chain, CDS/CDNSKEY) are appended in presentation form — an inspection artifact, not an import input.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone to export."),
            ExportZoneQuery
        ),
        responses(
            (status = 200, description = "The zone as master-file text", content_type = "text/plain", body = String),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
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
        ZoneView::from_signed(query.signed.unwrap_or(false)),
    )
    .await?;
    Ok((
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        zone_file,
    )
        .into_response())
}

/// The view switch of a zone export.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExportZoneQuery {
    /// Append the derived DNSSEC records.
    signed: Option<bool>,
}
