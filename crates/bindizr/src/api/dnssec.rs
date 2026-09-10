use axum::{
    Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_service::{
    dnssec::DnssecService,
    types::{
        DnssecStatusResponse, EnableDnssecRequest, ErrorResponse, MessageResponse,
        RolloverDnssecRequest, UpdateDnssecSettingsRequest,
    },
};
use serde::Deserialize;

use crate::api::{
    RequestCaller, ZoneNameParam,
    error::{ApiError, Path, Query},
    middleware::body_parser::JsonBody,
};

pub(crate) struct DnssecApi;

impl DnssecApi {
    pub(crate) async fn routes() -> Router {
        Router::new()
            .route("/zones/{name}/dnssec", routing::get(get_dnssec_status))
            .route("/zones/{name}/dnssec", routing::post(enable_dnssec))
            .route("/zones/{name}/dnssec", routing::delete(disable_dnssec))
            .route("/zones/{name}/dnssec", routing::put(update_dnssec_settings))
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
                "/zones/{name}/dnssec/check-ds",
                routing::post(check_dnssec_ds),
            )
    }
}

#[utoipa::path(
        get,
        path = "/zones/{name}/dnssec",
        tag = "DNSSEC",
        summary = "Get a zone's DNSSEC status",
        description = "Returns whether the zone is signed, the policy it signs under, its signing keys, their DS forms for the parent zone, the earliest stored signature expiration, and the zone serial. For an unsigned zone `enabled` is false with no policy and empty key and DS lists.",
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
        description = "Generates the zone's signing key(s) as the named DNSSEC policy prescribes (the built-in `default` policy — an ECDSA P-256 CSK with NSEC denial — when `policy` is omitted) and signs the whole zone. The response includes the DS records to register in the parent zone. `parent_ns_addrs` is required: it names the parent zone's nameservers that every later DS check asks.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        request_body = EnableDnssecRequest,
        responses(
            (status = 201, description = "DNSSEC enabled successfully", body = DnssecStatusResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone or DNSSEC policy not found", body = ErrorResponse),
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
        body.policy.as_deref(),
        &body.parent_ns_addrs,
    )
    .await?;
    let response = DnssecStatusResponse { dnssec: status };
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

#[derive(Deserialize)]
pub(crate) struct DisableDnssecQuery {
    pub(crate) skip_ds_check: Option<bool>,
}

#[utoipa::path(
        delete,
        path = "/zones/{name}/dnssec",
        tag = "DNSSEC",
        summary = "Disable DNSSEC for a zone",
        description = "Deletes the zone's signing keys and derived records, so secondaries unsign via IXFR. Dropping the signatures while the parent zone still publishes a DS makes the zone bogus, so the zone's parent nameservers (`parent_ns_addrs`) are asked first: refused while any serves a DS for the zone (`DNSSEC_DS_PUBLISHED`), fails to answer (`DNSSEC_DS_UNVERIFIED`), or was replaced while being asked (`DNSSEC_STATE_CHANGED`; retry). `skip_ds_check=true` skips the check; waiting out the DS TTL after its removal stays the caller's.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone."),
            ("skip_ds_check" = Option<bool>, Query, description = "Skip the parent DS check.")
        ),
        responses(
            (status = 200, description = "DNSSEC disabled successfully", body = MessageResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 409, description = "DNSSEC is not enabled for the zone, the parent still serves its DS, or the parent could not be asked", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Disable DNSSEC for a zone.
pub(crate) async fn disable_dnssec(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    Query(query): Query<DisableDnssecQuery>,
) -> Result<Response, ApiError> {
    DnssecService::disable(&caller, &params.name, query.skip_ds_check.unwrap_or(false)).await?;
    let response = MessageResponse {
        message: "DNSSEC disabled successfully".to_string(),
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
        description = "Pre-publishes a same-algorithm replacement key (RFC 7583) that signs no zone data until promoted; `role` selects the key for split-key zones. To change the algorithm, move the zone to a policy of the new algorithm (`policy` in `PUT /zones/{name}/dnssec`), which double-signs the zone through the transition (RFC 6840, Section 5.11).",
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

#[derive(Deserialize)]
pub(crate) struct DsSeenQuery {
    pub(crate) skip_ds_check: Option<bool>,
    pub(crate) skip_holddown: Option<bool>,
}

#[utoipa::path(
        post,
        path = "/zones/{name}/dnssec/rollover/ds-seen",
        tag = "DNSSEC",
        summary = "Confirm the new DS is at the parent (ds-seen)",
        description = "Promotes the pre-published key to active and retires the key it replaces, once the publish hold-down has passed and every one of the zone's parent nameservers (`parent_ns_addrs`) serves the new key's DS; refused with `DNSSEC_DS_NOT_PUBLISHED` while they do not, `DNSSEC_DS_UNVERIFIED` when they cannot be asked or answer only in a digest type bindizr cannot compute, or `DNSSEC_STATE_CHANGED` when the zone's keys or parent changed while they were being asked (retry). `skip_ds_check=true` takes the DS on the caller's word; `skip_holddown=true` promotes before the hold-down passes, at the cost of validation failures at resolvers still caching the previous DNSKEY set. Waiting out the parent's DS TTL after it appears stays the caller's. Retired keys are removed automatically once caches drain; ZSK rollovers involve no DS and are promoted automatically after a hold-down.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone."),
            ("skip_ds_check" = Option<bool>, Query, description = "Skip the parent DS check."),
            ("skip_holddown" = Option<bool>, Query, description = "Promote before the publish hold-down has passed.")
        ),
        responses(
            (status = 200, description = "Rollover advanced, new key promoted", body = DnssecStatusResponse),
            (status = 400, description = "Bad request: the rollover is ZSK-only (no DS to confirm), or the publish hold-down has not passed", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 409, description = "DNSSEC is not enabled for the zone, no rollover is in progress, the parent does not serve the new DS yet, or the parent could not be asked", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Confirm the new DS is at the parent, promoting the pre-published key(s).
pub(crate) async fn ds_seen_dnssec_rollover(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    Query(query): Query<DsSeenQuery>,
) -> Result<Response, ApiError> {
    let status = DnssecService::rollover_ds_seen(
        &caller,
        &params.name,
        query.skip_ds_check.unwrap_or(false),
        query.skip_holddown.unwrap_or(false),
    )
    .await?;
    let response = DnssecStatusResponse { dnssec: status };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[utoipa::path(
        post,
        path = "/zones/{name}/dnssec/withdraw",
        tag = "DNSSEC",
        summary = "Publish the DS withdrawal (RFC 8078 delete CDS/CDNSKEY)",
        description = "Replaces the zone's CDS/CDNSKEY records with the RFC 8078 delete pair (`CDS 0 0 0 00`), asking a CDS-consuming parent to remove the zone's DS records — the first step of going insecure. Once the parent DS is gone and its TTL has passed, disable DNSSEC.",
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
        delete,
        path = "/zones/{name}/dnssec/withdraw",
        tag = "DNSSEC",
        summary = "Cancel a published DS withdrawal",
        description = "Removes the RFC 8078 delete pair; the per-key CDS/CDNSKEY records return with this signing pass.",
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
        post,
        path = "/zones/{name}/dnssec/check-ds",
        tag = "DNSSEC",
        summary = "Ask the parent zone whether it serves the zone's DS",
        description = "Asks the zone's parent nameservers (`parent_ns_addrs`) for the zone's DS records and reports the answer in `delegation`: `published` with the key tags and TTL served, or `hidden`. The same check gates disabling DNSSEC.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        responses(
            (status = 200, description = "The parent's answer with the zone's DNSSEC status", body = DnssecStatusResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 409, description = "DNSSEC is not enabled for the zone, or the parent could not be asked", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Ask the parent zone whether it serves the zone's DS.
pub(crate) async fn check_dnssec_ds(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
) -> Result<Response, ApiError> {
    let status = DnssecService::check_ds(&caller, &params.name).await?;
    let response = DnssecStatusResponse { dnssec: status };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[utoipa::path(
        put,
        path = "/zones/{name}/dnssec",
        tag = "DNSSEC",
        summary = "Change a zone's DNSSEC settings",
        description = "Applies the given fields in one transaction; an omitted field keeps its value. `policy` moves a signed zone to another policy: the denial mode and key layout must match the current policy's (they are fixed while signed; disable and re-enable to change them), and a different algorithm starts an algorithm rollover that double-signs the zone until the old keys leave after ds-seen (RFC 6840, Section 5.11). `parent_ns_addrs` names the parent zone's nameservers asked for the zone's DS, as comma-separated `host[:port]` entries; the list must name at least one server, and it applies to unsigned zones too.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        request_body = UpdateDnssecSettingsRequest,
        responses(
            (status = 200, description = "Settings changed", body = DnssecStatusResponse),
            (status = 400, description = "Bad request: no field given, an invalid parent address, or a policy whose denial mode or key layout differs from the zone's", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone or DNSSEC policy not found", body = ErrorResponse),
            (status = 409, description = "A policy was given for a zone without DNSSEC, or a rollover is already in progress", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Change a zone's DNSSEC settings.
pub(crate) async fn update_dnssec_settings(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    JsonBody(body): JsonBody<UpdateDnssecSettingsRequest>,
) -> Result<Response, ApiError> {
    let status = DnssecService::update_settings(
        &caller,
        &params.name,
        body.policy.as_deref(),
        body.parent_ns_addrs.as_deref(),
    )
    .await?;
    let response = DnssecStatusResponse { dnssec: status };
    Ok((StatusCode::OK, Json(response)).into_response())
}
