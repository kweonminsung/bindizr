//! Zone HTTP routes; each operation group owns its extractors and response mapping.

mod crud;
mod export;
mod history;
mod import;
mod status;

use std::sync::Arc;

use axum::{Router, extract::DefaultBodyLimit, routing};
use bindizr_service::Context;
pub(crate) use crud::{
    __path_create_zone, __path_delete_zone, __path_get_zone, __path_list_zones, __path_update_zone,
    create_zone, delete_zone, get_zone, list_zones, update_zone,
};
pub(crate) use export::{__path_export_zone, export_zone};
pub(crate) use history::{
    __path_diff_zone_versions, __path_get_zone_version, __path_list_zone_versions,
    __path_rollback_zone, diff_zone_versions, get_zone_version, list_zone_versions, rollback_zone,
};
pub(crate) use import::{__path_import_zone, __path_import_zones, import_zone, import_zones};
pub(crate) use status::{__path_get_zone_status, get_zone_status};

use crate::api::middleware::body_parser::MAX_UPLOAD_BODY_BYTES;

/// Build the zone API routes.
pub(crate) fn routes() -> Router<Arc<Context>> {
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
        .route(
            "/import",
            routing::post(import_zones).layer(DefaultBodyLimit::max(MAX_UPLOAD_BODY_BYTES)),
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
