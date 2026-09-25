//! HTTP API server: routing, middleware, and the zone/record/notify endpoints.

mod dnssec;
mod dnssec_policy;
mod error;
mod external_dns;
mod health;
mod metrics;
mod middleware;
mod notify;
mod openapi;
mod record;
mod router;
mod secondary;
mod token;
mod tsig_key;
mod zone;

use std::{net::SocketAddr, time::Duration};

use axum::{extract::FromRequestParts, http::request::Parts};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use bindizr_core::{config, config::TlsFiles, model::api_token::ApiToken};
use bindizr_service::{authorization::Caller, error::ServiceError};
use error::ApiError;
use router::ApiRouter;
use serde::Deserialize;
use tokio::{net::TcpListener, task::JoinHandle};

use crate::{cli::error::CliError, shutdown::Shutdown};

#[derive(Debug, Deserialize)]
pub(crate) struct NameParam {
    pub(crate) name: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct IdParam {
    pub(crate) id: i32,
}

#[derive(Debug, Deserialize)]
pub(crate) struct NameIdParam {
    pub(crate) name: String,
    pub(crate) id: i32,
}

/// The preview switch every endpoint that offers one reads, so they all spell
/// it the same way and an absent one is the same as `false`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DryRunQuery {
    #[serde(default)]
    pub(crate) dry_run: bool,
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

    /// Extract the authorized caller from request extensions.
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, ApiError> {
        parts
            .extensions
            .get::<Caller>()
            .cloned()
            .map(RequestCaller)
            .ok_or_else(|| ApiError(ServiceError::unauthorized("Request has no caller identity")))
    }
}

/// The token a request authenticated with, attached by the auth middleware;
/// absent (so a 401) when authentication is disabled.
#[derive(Clone)]
pub(crate) struct AuthenticatedToken(pub(crate) ApiToken);

impl<S> FromRequestParts<S> for AuthenticatedToken
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    /// Extract the authenticated API token from request extensions.
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, ApiError> {
        parts
            .extensions
            .get::<AuthenticatedToken>()
            .cloned()
            .ok_or_else(|| ApiError(ServiceError::unauthorized("Request carries no API token")))
    }
}

/// How long a TLS shutdown waits for in-flight requests before dropping the
/// connections; the plain-HTTP path waits without a deadline, as axum does.
const TLS_SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// Bind the HTTP API listener and spawn the server in the background, over TLS
/// when `api.tls_cert_file` and `api.tls_key_file` name a pair. The returned
/// handle finishes once `shutdown` fires and in-flight requests are answered.
pub(crate) async fn initialize(shutdown: &Shutdown) -> Result<JoinHandle<()>, CliError> {
    let bindizr_config = config::bindizr_config();
    let addr = SocketAddr::from((
        bindizr_config.api.listen_addr,
        bindizr_config.api.listen_port,
    ));

    // Bound here rather than inside the server so a taken port fails startup
    // instead of surfacing in a background task.
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("Failed to bind the HTTP API to {}: {}", addr, e))?;

    let Some(TlsFiles {
        cert_file,
        key_file,
    }) = bindizr_config.api.tls_files()
    else {
        log::info!("HTTP API server listening on http://{}", addr);
        let stop = shutdown.waiter();
        return Ok(tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, ApiRouter::routes().await)
                .with_graceful_shutdown(stop)
                .await
            {
                log::error!("API server error: {:?}", e);
            }
        }));
    };

    // A pair that cannot be read is permanent, so it exits as a configuration
    // failure rather than looping through systemd's restart.
    let tls = RustlsConfig::from_pem_file(cert_file, key_file)
        .await
        .map_err(|e| {
            CliError::configuration(format!(
                "Failed to read the API TLS certificate '{}' and key '{}': {}",
                cert_file, key_file, e
            ))
        })?;
    let listener = listener.into_std().map_err(|e| {
        format!(
            "Failed to hand the HTTP API listener to the TLS server: {}",
            e
        )
    })?;
    let server = axum_server::from_tcp_rustls(listener, tls)
        .map_err(|e| format!("Failed to start the HTTPS API server on {}: {}", addr, e))?;

    log::info!("HTTP API server listening on https://{}", addr);

    let handle = Handle::new();
    let stop = shutdown.waiter();
    let stopping = handle.clone();
    tokio::spawn(async move {
        stop.await;
        stopping.graceful_shutdown(Some(TLS_SHUTDOWN_GRACE));
    });
    Ok(tokio::spawn(async move {
        if let Err(e) = server
            .handle(handle)
            .serve(ApiRouter::routes().await.into_make_service())
            .await
        {
            log::error!("API server error: {:?}", e);
        }
    }))
}
