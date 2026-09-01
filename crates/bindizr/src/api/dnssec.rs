use axum::{
    Json, Router,
    extract::{Path, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_service::{
    dnssec::DnssecService,
    types::{
        DnssecDsListResponse, DnssecStatusResponse, EnableDnssecRequest, ErrorResponse,
        MessageResponse, RolloverDnssecRequest, SetDnssecTimingRequest, VerifyDnssecResponse,
    },
};
use serde::Deserialize;

use crate::{
    api::{RequestCaller, ZoneNameParam, error::ApiError, middleware::body_parser::JsonBody},
    dns,
};

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
            .route(
                "/zones/{name}/dnssec/withdraw",
                routing::post(withdraw_dnssec).delete(cancel_dnssec_withdrawal),
            )
            .route(
                "/zones/{name}/dnssec/timing",
                routing::put(set_dnssec_timing),
            )
            .route("/zones/{name}/dnssec/verify", routing::get(verify_dnssec))
    }
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
        description = "Generates the zone's signing key — an ECDSA P-256 CSK by default (`algorithm` also accepts `ecdsap384sha384`, `ed25519`, `ed448`, `rsasha256`, and `rsasha512`; `split_keys` generates a KSK/ZSK pair instead; `nsec3` selects NSEC3 denial of existence) — and signs the whole zone. The response includes the DS records to register in the parent zone.",
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
        description = "Pre-publishes replacement keys (RFC 7583). Without `algorithm` the replacement keeps the current one and signs no zone data until promoted; `role` selects the key for split-key zones. With `algorithm` every key is replaced and the zone is double-signed through the transition (RFC 6840, Section 5.11) until the old keys leave after ds-seen.",
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
    let status = DnssecService::rollover_start(
        &caller,
        &params.name,
        body.role.as_deref(),
        body.algorithm.as_deref(),
    )
    .await?;
    let response = DnssecStatusResponse { dnssec: status };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Query parameters for the ds-seen confirmation.
#[derive(Deserialize)]
pub(crate) struct DsSeenQuery {
    pub(crate) force: Option<bool>,
}

#[utoipa::path(
        post,
        path = "/zones/{name}/dnssec/rollover/ds-seen",
        tag = "DNSSEC",
        summary = "Confirm the new DS is at the parent (ds-seen)",
        description = "The operator's confirmation that the new DS record has been seen at the parent zone and its TTL has passed (the `ds-seen` step, as in OpenDNSSEC/BIND). Promotes the pre-published key to active and retires the key it replaces; retired keys are removed automatically once caches drain. ZSK rollovers involve no DS and are promoted automatically after a hold-down.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone."),
            ("force" = Option<bool>, Query, description = "Skip the parent DS verification against dnssec.ds_probe_resolver.")
        ),
        responses(
            (status = 200, description = "Rollover advanced, new key promoted", body = DnssecStatusResponse),
            (status = 400, description = "Bad request: the rollover is ZSK-only (no DS to confirm), the publish hold-down has not passed, or the parent DS is not visible at the configured resolver", body = ErrorResponse),
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
    Query(query): Query<DsSeenQuery>,
) -> Result<Response, ApiError> {
    let status =
        dns::rollover::confirm_ds_seen(&caller, &params.name, query.force.unwrap_or(false)).await?;
    let response = DnssecStatusResponse { dnssec: status };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[utoipa::path(
        post,
        path = "/zones/{name}/dnssec/withdraw",
        tag = "DNSSEC",
        summary = "Publish the DS withdrawal (RFC 8078 delete CDS/CDNSKEY)",
        description = "Replaces the zone's CDS/CDNSKEY set with the RFC 8078 delete pair (`CDS 0 0 0 00`), asking a CDS-consuming parent to remove the zone's DS records — the first step of going insecure. Once the parent DS is gone and its TTL has passed, disable DNSSEC.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        responses(
            (status = 200, description = "Withdrawal published", body = DnssecStatusResponse),
            (status = 400, description = "Bad request, the withdrawal is already published", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 409, description = "DNSSEC is not enabled for the zone", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Publish the RFC 8078 delete CDS/CDNSKEY pair.
pub(crate) async fn withdraw_dnssec(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
) -> Result<Response, ApiError> {
    let status = DnssecService::withdraw(&caller, &params.name).await?;
    let response = DnssecStatusResponse { dnssec: status };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[utoipa::path(
        put,
        path = "/zones/{name}/dnssec/timing",
        tag = "DNSSEC",
        summary = "Replace a zone's DNSSEC timing overrides",
        description = "Replaces the zone's signing-timing overrides (signature validity, re-sign threshold, scheduled ZSK lifetime). An omitted field reverts that knob to the global `[dnssec]` config. Takes effect on the next signing pass or maintenance scan.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        request_body = SetDnssecTimingRequest,
        responses(
            (status = 200, description = "Timing overrides replaced", body = DnssecStatusResponse),
            (status = 400, description = "Bad request", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Replace the zone's DNSSEC timing overrides.
pub(crate) async fn set_dnssec_timing(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    JsonBody(body): JsonBody<SetDnssecTimingRequest>,
) -> Result<Response, ApiError> {
    let status = DnssecService::set_timing(&caller, &params.name, body).await?;
    let response = DnssecStatusResponse { dnssec: status };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[utoipa::path(
        delete,
        path = "/zones/{name}/dnssec/withdraw",
        tag = "DNSSEC",
        summary = "Cancel a published DS withdrawal",
        description = "Removes the RFC 8078 delete pair; the per-key CDS/CDNSKEY set returns with this signing pass.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        responses(
            (status = 200, description = "Withdrawal cancelled", body = DnssecStatusResponse),
            (status = 400, description = "Bad request, no withdrawal is published", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 409, description = "DNSSEC is not enabled for the zone", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Cancel a published DS withdrawal.
pub(crate) async fn cancel_dnssec_withdrawal(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
) -> Result<Response, ApiError> {
    let status = DnssecService::withdraw_cancel(&caller, &params.name).await?;
    let response = DnssecStatusResponse { dnssec: status };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[utoipa::path(
        get,
        path = "/zones/{name}/dnssec/verify",
        tag = "DNSSEC",
        summary = "Verify a zone's DNSSEC state",
        description = "Runs self-checks on the stored state — key inventory, signature freshness, per-algorithm signature coverage (RFC 6840, Section 5.11), and the denial chain — and, with `dnssec.ds_probe_resolver` configured, compares the DS the parent serves against the zone's keys. Each aspect reports as a named check; `ok` is the conjunction.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        responses(
            (status = 200, description = "Verification report", body = VerifyDnssecResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 409, description = "DNSSEC is not enabled for the zone", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Verify a zone's DNSSEC state.
pub(crate) async fn verify_dnssec(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
) -> Result<Response, ApiError> {
    let response = dns::verify::verify(&caller, &params.name).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}
