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
        MessageResponse, RolloverDnssecRequest, SetDnssecParentNsAddrsRequest,
        SetZoneDnssecPolicyRequest,
    },
};
use serde::Deserialize;

use crate::api::{
    RequestCaller, ZoneNameParam, error::ApiError, middleware::body_parser::JsonBody,
};

pub(crate) struct DnssecApi;

impl DnssecApi {
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
                "/zones/{name}/dnssec/policy",
                routing::put(set_zone_dnssec_policy),
            )
            .route(
                "/zones/{name}/dnssec/check-ds",
                routing::post(check_dnssec_ds),
            )
            .route(
                "/zones/{name}/dnssec/parent-ns-addrs",
                routing::put(set_dnssec_parent_ns_addrs),
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
        description = "Generates the zone's signing key(s) as the named DNSSEC policy prescribes (the built-in `default` policy — an ECDSA P-256 CSK with NSEC denial — when `policy` is omitted) and signs the whole zone. The response includes the DS records to register in the parent zone. `parent_ns_addrs` names the parent zone's nameservers that disabling DNSSEC later asks for the DS; omitted, the parent is discovered through the system resolver.",
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
        body.parent_ns_addrs.as_deref(),
    )
    .await?;
    let response = DnssecStatusResponse { dnssec: status };
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

#[derive(Deserialize)]
pub(crate) struct DisableDnssecQuery {
    pub(crate) force: Option<bool>,
}

#[utoipa::path(
        delete,
        path = "/zones/{name}/dnssec",
        tag = "DNSSEC",
        summary = "Disable DNSSEC for a zone",
        description = "Deletes the zone's signing keys and derived records, so secondaries unsign via IXFR. Dropping the signatures while the parent zone still publishes a DS makes the zone bogus, so the parent's nameservers (`parent_ns_addrs`, or the discovered ones) are asked first: refused while any serves a DS for the zone (`DNSSEC_DS_PUBLISHED`) or fails to answer (`DNSSEC_DS_UNVERIFIED`). `force=true` skips the check; waiting out the DS TTL after its removal stays the caller's.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone."),
            ("force" = Option<bool>, Query, description = "Skip the parent DS check.")
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
    DnssecService::disable(&caller, &params.name, query.force.unwrap_or(false)).await?;
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
        description = "Pre-publishes a same-algorithm replacement key (RFC 7583) that signs no zone data until promoted; `role` selects the key for split-key zones. To change the algorithm, move the zone to a policy of the new algorithm (`PUT /zones/{name}/dnssec/policy`), which double-signs the zone through the transition (RFC 6840, Section 5.11).",
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
        description = "The operator's confirmation that the new DS record has been seen at the parent zone and its TTL has passed (the `ds-seen` step, as in OpenDNSSEC/BIND); bindizr does not check the parent itself. Promotes the pre-published key to active and retires the key it replaces; retired keys are removed automatically once caches drain. ZSK rollovers involve no DS and are promoted automatically after a hold-down.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        responses(
            (status = 200, description = "Rollover advanced, new key promoted", body = DnssecStatusResponse),
            (status = 400, description = "Bad request: the rollover is ZSK-only (no DS to confirm), or the publish hold-down has not passed", body = ErrorResponse),
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
        put,
        path = "/zones/{name}/dnssec/policy",
        tag = "DNSSEC",
        summary = "Move a signed zone to another DNSSEC policy",
        description = "Points the zone at another policy. The denial mode and key layout must match the current policy's (they are fixed while signed; disable and re-enable to change them). A different algorithm starts an algorithm rollover under the new policy: every key gets a pre-published replacement and the zone is double-signed until the old keys leave after ds-seen (RFC 6840, Section 5.11). Timing changes take effect on the next signing pass.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        request_body = SetZoneDnssecPolicyRequest,
        responses(
            (status = 200, description = "Policy changed", body = DnssecStatusResponse),
            (status = 400, description = "Bad request: the policy's denial mode or key layout differs from the zone's", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone or DNSSEC policy not found", body = ErrorResponse),
            (status = 409, description = "DNSSEC is not enabled for the zone, or a rollover is already in progress", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Move a signed zone to another DNSSEC policy.
pub(crate) async fn set_zone_dnssec_policy(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    JsonBody(body): JsonBody<SetZoneDnssecPolicyRequest>,
) -> Result<Response, ApiError> {
    let status = DnssecService::set_policy(&caller, &params.name, &body.policy).await?;
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
        description = "Asks the parent zone's nameservers (`parent_ns_addrs`, or the discovered ones) for the zone's DS records and reports the answer in `delegation`: `published` with the key tags and TTL served, or `hidden`. The same check gates disabling DNSSEC.",
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
        path = "/zones/{name}/dnssec/parent-ns-addrs",
        tag = "DNSSEC",
        summary = "Set the parent zone's nameservers of a zone",
        description = "Sets the parent zone's nameservers asked for the zone's DS, as comma-separated `host[:port]` entries; null or empty returns the zone to discovering its parent. Needed where the parent is private, unreachable from bindizr, or undiscoverable without a system resolver.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        request_body = SetDnssecParentNsAddrsRequest,
        responses(
            (status = 200, description = "Parent nameservers set", body = DnssecStatusResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Set the parent zone's servers of a zone.
pub(crate) async fn set_dnssec_parent_ns_addrs(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    JsonBody(body): JsonBody<SetDnssecParentNsAddrsRequest>,
) -> Result<Response, ApiError> {
    let status =
        DnssecService::set_parent_ns_addrs(&caller, &params.name, body.parent_ns_addrs.as_deref())
            .await?;
    let response = DnssecStatusResponse { dnssec: status };
    Ok((StatusCode::OK, Json(response)).into_response())
}
