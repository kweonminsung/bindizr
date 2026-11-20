use axum::Json;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use bindizr_service::error::ServiceError;
use utoipa::openapi::security::{Http, HttpAuthScheme, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::api::error::ApiError;

/// OpenAPI document for the HTTP API, served when `api.openapi_enabled` is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, OpenApi)]
#[openapi(
    paths(
        crate::api::health::handle_health,
        crate::api::zone::list_zones,
        crate::api::zone::get_zone,
        crate::api::zone::create_zone,
        crate::api::zone::update_zone,
        crate::api::zone::delete_zone,
        crate::api::record::list_records,
        crate::api::record::get_record,
        crate::api::record::create_record,
        crate::api::record::update_record,
        crate::api::record::delete_record,
        crate::api::record::delete_matching_records,
        crate::api::record::create_bulk_records,
        crate::api::zone::import_zone,
        crate::api::zone::import_zones,
        crate::api::zone::export_zone,
        crate::api::zone::list_zone_versions,
        crate::api::zone::get_zone_version,
        crate::api::zone::diff_zone_versions,
        crate::api::zone::rollback_zone,
        crate::api::zone::get_zone_status,
        crate::api::notify::notify_all_zones,
        crate::api::notify::notify_zone,
        crate::api::secondary::list_secondaries,
        crate::api::secondary::create_secondary,
        crate::api::secondary::get_secondary,
        crate::api::secondary::update_secondary,
        crate::api::secondary::delete_secondary,
        crate::api::secondary::check_secondary,
        crate::api::tsig_key::list_tsig_keys,
        crate::api::tsig_key::create_tsig_key,
        crate::api::tsig_key::get_tsig_key,
        crate::api::tsig_key::delete_tsig_key,
        crate::api::token::list_tokens,
        crate::api::token::create_token,
        crate::api::token::get_self_token,
        crate::api::token::list_self_token_grants,
        crate::api::token::delete_token,
        crate::api::role::list_roles,
        crate::api::role::create_role,
        crate::api::role::get_role,
        crate::api::role::delete_role,
        crate::api::role::list_role_grants,
        crate::api::role::create_role_grant,
        crate::api::role::delete_role_grant,
        crate::api::permission::get_permissions,
        crate::api::logs::list_audit_logs,
        crate::api::logs::list_access_logs,
        crate::api::logs::list_transfer_logs,
        crate::api::dnssec::get_dnssec_status,
        crate::api::dnssec::enable_dnssec,
        crate::api::dnssec::disable_dnssec,
        crate::api::dnssec::sign_zone,
        crate::api::dnssec::start_dnssec_rollover,
        crate::api::dnssec::advance_dnssec_rollover,
        crate::api::dnssec::withdraw_dnssec,
        crate::api::dnssec::update_dnssec_settings,
        crate::api::dnssec::cancel_dnssec_withdrawal,
        crate::api::dnssec::check_dnssec_ds,
        crate::api::dnssec_policy::list_dnssec_policies,
        crate::api::dnssec_policy::create_dnssec_policy,
        crate::api::dnssec_policy::get_dnssec_policy,
        crate::api::dnssec_policy::update_dnssec_policy,
        crate::api::dnssec_policy::delete_dnssec_policy,
        crate::api::external_dns::list_external_dns_domains,
        crate::api::external_dns::list_external_dns_records,
        crate::api::external_dns::apply_external_dns_changes,
        crate::api::external_dns::adjust_external_dns_records
    ),
    // Global requirement; /health opts out with an empty per-path security.
    security(
        ("bearer_auth" = [])
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "Health", description = "Service health probe for load balancers and orchestrators."),
        (name = "Zone", description = "Manage DNS zones including creation, update, deletion, and retrieval."),
        (name = "Record", description = "Manage DNS records including creation, update, deletion, and retrieval."),
        (name = "Notify", description = "Send DNS NOTIFY messages to secondary servers."),
        (name = "Secondary", description = "The secondary servers: each receives NOTIFY, may pull zones unsigned from its address, and is probed for the serial it serves."),
        (name = "TSIG", description = "Manage TSIG keys, each authenticating nsupdate and transfers into a role."),
        (name = "Token", description = "API tokens, each authenticating into a role."),
        (name = "Role", description = "Roles and their grants: the actions API tokens and TSIG keys holding a role may perform."),
        (name = "Log", description = "What Bindizr changed, served and answered, read back under `log:read`: the audit log of management changes, the access log of API requests and nsupdates, and the transfer log of zone transfers."),
        (name = "DNSSEC", description = "DNSSEC policies (the signing-parameter bundles zones sign under) and per-zone signing: enable, disable, status, DS records for the parent zone and the parent's check of them, key rollover, and re-signing."),
        (name = "ExternalDNS", description = "Provider endpoints for the ExternalDNS webhook adapter; registered only when api.external_dns_enabled is set.")
    ),
    info(
        title = "Bindizr HTTP API",
        version = env!("CARGO_PKG_VERSION"),
        description = "This is the API documentation for Bindizr",
        contact(email = "kevin136583@gmail.com"),
        license(name = "Apache 2.0", url = "http://www.apache.org/licenses/LICENSE-2.0.html")
    )
)]
struct ApiDoc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SecurityAddon;

impl Modify for SecurityAddon {
    /// Add bearer-token authentication to the OpenAPI document.
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
            );
        }
    }
}

/// Return the OpenAPI document as JSON.
pub(crate) async fn handle_openapi_json() -> Response {
    (StatusCode::OK, Json(ApiDoc::openapi())).into_response()
}

/// Return the OpenAPI document as YAML.
pub(crate) async fn handle_openapi_yaml() -> Response {
    match serde_norway::to_string(&ApiDoc::openapi()) {
        Ok(openapi_yaml) => (
            StatusCode::OK,
            [(CONTENT_TYPE, "application/yaml; charset=utf-8")],
            openapi_yaml,
        )
            .into_response(),
        Err(error) => ApiError(ServiceError::internal_with_source(
            "failed to generate OpenAPI YAML",
            error,
        ))
        .into_response(),
    }
}

/// Return the API error for the OpenAPI document while it is not served.
pub(crate) async fn handle_openapi_disabled() -> Response {
    ApiError(ServiceError::EndpointNotFound(
        "the OpenAPI document is not served; set api.openapi_enabled = true to serve it"
            .to_string(),
    ))
    .into_response()
}
