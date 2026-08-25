use axum::{
    Json, Router,
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_service::{
    dnssec::DnssecService,
    types::{
        DnssecDsListResponse, DnssecStatusResponse, EnableDnssecRequest, ErrorResponse,
        MessageResponse, RolloverDnssecRequest,
    },
};
use serde::Deserialize;

use crate::api::{RequestCaller, error::ApiError, middleware::body_parser::JsonBody};

/// Route group for zone DNSSEC endpoints.
pub(crate) struct DnssecApi;

impl DnssecApi {
    /// Build the router for zone DNSSEC endpoints.
    pub(crate) async fn routes() -> Router {
        Router::new()
            .route("/zones/{name}/dnssec", routing::get(get_dnssec_status))
            .route("/zones/{name}/dnssec", routing::post(enable_dnssec))
            .route("/zones/{name}/dnssec", routing::delete(disable_dnssec))
            .route(
                "/zones/{name}/dnssec/ds",
                routing::get(get_dnssec_ds_records),
            )
            .route("/zones/{name}/dnssec/sign", routing::post(sign_zone))
            .route(
                "/zones/{name}/dnssec/rollover",
                routing::post(start_dnssec_rollover),
            )
            .route(
                "/zones/{name}/dnssec/rollover/ds-seen",
                routing::post(ds_seen_dnssec_rollover),
            )
    }
}

#[derive(Deserialize)]
pub(crate) struct ZoneNameParam {
    pub(crate) name: String,
}

#[utoipa::path(
        get,
        path = "/zones/{name}/dnssec",
        tag = "DNSSEC",
        summary = "Get a zone's DNSSEC status",
        description = "Returns whether the zone is signed, its signing keys, their DS forms for the parent zone, the earliest stored signature expiration, and the zone serial. For an unsigned zone `enabled` is false with empty key and DS lists.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        responses(
            (status = 200, description = "The zone's DNSSEC status", body = DnssecStatusResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Report the DNSSEC signing state of a zone.
pub(crate) async fn get_dnssec_status(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
) -> Result<Response, ApiError> {
    let status = DnssecService::get_status(&caller, &params.name).await?;
    let response = DnssecStatusResponse { dnssec: status };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[utoipa::path(
        post,
        path = "/zones/{name}/dnssec",
        tag = "DNSSEC",
        summary = "Enable DNSSEC for a zone",
        description = "Generates the zone's signing key — an ECDSA P-256 CSK by default (`algorithm` also accepts `ed25519`; `split_keys` generates a KSK/ZSK pair instead; `nsec3` selects NSEC3 denial of existence) — and signs the whole zone. The response includes the DS records to register in the parent zone.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        request_body = EnableDnssecRequest,
        responses(
            (status = 201, description = "DNSSEC enabled successfully", body = DnssecStatusResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 409, description = "DNSSEC is already enabled for the zone", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Enable DNSSEC for a zone: generate its signing key and sign the zone.
pub(crate) async fn enable_dnssec(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    JsonBody(body): JsonBody<EnableDnssecRequest>,
) -> Result<Response, ApiError> {
    let status = DnssecService::enable(
        &caller,
        &params.name,
        body.algorithm.as_deref(),
        body.denial.as_deref(),
        body.split_keys,
    )
    .await?;
    let response = DnssecStatusResponse { dnssec: status };
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

#[utoipa::path(
        delete,
        path = "/zones/{name}/dnssec",
        tag = "DNSSEC",
        summary = "Disable DNSSEC for a zone",
        description = "Deletes the zone's signing keys and derived records, so secondaries unsign via IXFR. While the parent zone still publishes a DS record, dropping the signatures makes the zone bogus for validating resolvers: remove the DS and wait out its TTL before calling this.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        responses(
            (status = 200, description = "DNSSEC disabled successfully", body = MessageResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 409, description = "DNSSEC is not enabled for the zone", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Disable DNSSEC for a zone.
pub(crate) async fn disable_dnssec(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
) -> Result<Response, ApiError> {
    DnssecService::disable(&caller, &params.name).await?;
    let response = MessageResponse {
        message: "DNSSEC disabled successfully".to_string(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[utoipa::path(
        get,
        path = "/zones/{name}/dnssec/ds",
        tag = "DNSSEC",
        summary = "List a zone's DS records",
        description = "Returns the DS records of the zone's signing keys, in parsed fields and full presentation form, for registration in the parent zone. Empty for an unsigned zone.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        responses(
            (status = 200, description = "The zone's DS records", body = DnssecDsListResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// List the DS records of a zone's signing keys.
pub(crate) async fn get_dnssec_ds_records(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
) -> Result<Response, ApiError> {
    let status = DnssecService::get_status(&caller, &params.name).await?;
    let response = DnssecDsListResponse {
        ds_records: status.ds_records,
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[utoipa::path(
        post,
        path = "/zones/{name}/dnssec/sign",
        tag = "DNSSEC",
        summary = "Re-sign a zone from scratch",
        description = "Discards the zone's stored signatures and re-signs everything — a recovery hatch when stored signing state is doubted. Routine renewal happens automatically as records change and signatures approach expiry.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        responses(
            (status = 200, description = "Zone signed successfully", body = MessageResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 409, description = "DNSSEC is not enabled for the zone", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Re-sign a zone from scratch, discarding stored signatures.
pub(crate) async fn sign_zone(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
) -> Result<Response, ApiError> {
    DnssecService::sign(&caller, &params.name).await?;
    let response = MessageResponse {
        message: "Zone signed successfully".to_string(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[utoipa::path(
        post,
        path = "/zones/{name}/dnssec/rollover",
        tag = "DNSSEC",
        summary = "Start a key rollover for a zone",
        description = "Pre-publishes a replacement key with the same algorithm (RFC 7583): the new key joins the DNSKEY RRset — and, for SEP keys, the CDS/CDNSKEY set — but signs no zone data until the ds-seen call promotes it. For split-key zones `role` selects which key to roll (`ksk` or `zsk`); for CSK zones it is omitted.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        request_body = RolloverDnssecRequest,
        responses(
            (status = 200, description = "Rollover started, replacement key pre-published", body = DnssecStatusResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 409, description = "DNSSEC is not enabled for the zone, or a rollover is already in progress", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Start a key rollover: pre-publish a replacement key.
pub(crate) async fn start_dnssec_rollover(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    JsonBody(body): JsonBody<RolloverDnssecRequest>,
) -> Result<Response, ApiError> {
    let status = DnssecService::rollover_start(&caller, &params.name, body.role.as_deref()).await?;
    let response = DnssecStatusResponse { dnssec: status };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[utoipa::path(
        post,
        path = "/zones/{name}/dnssec/rollover/ds-seen",
        tag = "DNSSEC",
        summary = "Confirm the new DS is at the parent (ds-seen)",
        description = "The operator's confirmation that the new DS record has been seen at the parent zone and its TTL has passed (the `ds-seen` step, as in OpenDNSSEC/BIND). Promotes the pre-published key to active and retires the key it replaces; retired keys are removed automatically once caches drain. ZSK rollovers involve no DS and are promoted automatically after a hold-down.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        responses(
            (status = 200, description = "Rollover advanced, new key promoted", body = DnssecStatusResponse),
            (status = 400, description = "Bad request, the rollover is ZSK-only (no DS to confirm) or the publish hold-down has not passed", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 409, description = "DNSSEC is not enabled for the zone, or no rollover is in progress", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Confirm the new DS is at the parent, promoting the pre-published key(s).
pub(crate) async fn ds_seen_dnssec_rollover(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
) -> Result<Response, ApiError> {
    let status = DnssecService::rollover_ds_seen(&caller, &params.name).await?;
    let response = DnssecStatusResponse { dnssec: status };
    Ok((StatusCode::OK, Json(response)).into_response())
}
