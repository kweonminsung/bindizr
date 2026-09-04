//! HTTP API server: routing, middleware, and the zone/record/notify endpoints.

pub(crate) mod dnssec;
pub(crate) mod dnssec_policy;
pub(crate) mod error;
pub(crate) mod external_dns;
pub(crate) mod health;
pub(crate) mod metrics;
pub(crate) mod middleware;
pub(crate) mod notify;
pub(crate) mod openapi;
pub(crate) mod record;
pub(crate) mod router;
pub(crate) mod token_policy;
pub(crate) mod tsig_key;
pub(crate) mod zone;

use std::net::SocketAddr;

use axum::{extract::FromRequestParts, http::request::Parts};
use bindizr_core::{config, log_error, log_info};
use bindizr_service::{authorization::Caller, error::ServiceError};
use error::ApiError;
use router::ApiRouter;
use serde::Deserialize;
use tokio::net::TcpListener;

#[derive(Debug, Deserialize)]
pub(crate) struct ZoneNameParam {
    pub(crate) name: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ZonePolicyParam {
    pub(crate) name: String,
    pub(crate) id: i32,
}

/// The caller attached by the auth middleware, or by the router's
/// `Caller::Global` layer when authentication is disabled. A request without
/// one reached a handler outside both layers, so extraction fails closed.
pub(crate) struct RequestCaller(pub(crate) Caller);

impl<S> FromRequestParts<S> for RequestCaller
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, ApiError> {
        parts
            .extensions
            .get::<Caller>()
            .cloned()
            .map(RequestCaller)
            .ok_or_else(|| ApiError(ServiceError::unauthorized("Request has no caller identity")))
    }
}

/// Bind the HTTP API listener and spawn the axum server in the background.
pub(crate) async fn initialize() -> Result<(), String> {
    let bindizr_config = config::bindizr_config();
    let addr = SocketAddr::from((
        bindizr_config.api.listen_addr,
        bindizr_config.api.listen_port,
    ));

    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("Failed to bind the HTTP API to {}: {}", addr, e))?;

    log_info!("HTTP API server listening on http://{}", addr);

    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, ApiRouter::routes().await).await {
            log_error!("API server error: {:?}", e);
        }
    });

    Ok(())
}
