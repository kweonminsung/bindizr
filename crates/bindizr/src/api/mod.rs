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
mod permission;
mod query;
mod record;
mod role;
mod router;
mod secondary;
mod token;
mod tsig_key;
mod zone;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{extract::FromRequestParts, http::request::Parts};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use bindizr_core::model::api_token::ApiToken;
use bindizr_service::{Context, authorization::Caller, error::ServiceError};
use error::ApiError;
use rustls::ServerConfig;
use thiserror::Error;
use tokio::{net::TcpListener, task::JoinHandle};

use crate::{shutdown::Shutdown, tls::TlsCertificate};

/// The caller attached by the auth middleware, or by the router's
/// `Caller::unauthenticated_api()` layer when authentication is disabled. A request without
/// one reached a handler outside both layers, so extraction fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
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
            .ok_or_else(|| ApiError(ServiceError::unauthorized("request has no caller identity")))
    }
}

/// The token a request authenticated with, attached by the auth middleware;
/// absent (so a 401) when authentication is disabled.
#[derive(Debug, Clone, PartialEq, Eq)]
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
            .ok_or_else(|| ApiError(ServiceError::unauthorized("request carries no API token")))
    }
}

/// How long a TLS shutdown waits for in-flight requests before dropping the
/// connections; the plain-HTTP path waits without a deadline, as axum does.
const TLS_SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// Why the HTTP API could not come up.
#[derive(Debug, Error)]
pub(crate) enum StartApiError {
    #[error("failed to bind the HTTP API to {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to hand the HTTP API listener to the TLS server: {0}")]
    IntoStd(#[source] std::io::Error),
    #[error("failed to start the HTTPS API server on {addr}: {source}")]
    Serve {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

/// Bind the HTTP API listener and spawn the server in the background, over TLS
/// when `api.tls` named a certificate and key. The returned
/// handle finishes once `shutdown` fires and in-flight requests are answered.
pub(crate) async fn initialize(
    cx: Arc<Context>,
    shutdown: &Shutdown,
    certificate: Option<Arc<TlsCertificate>>,
) -> Result<JoinHandle<()>, StartApiError> {
    let bindizr_config = cx.config();
    let addr = SocketAddr::from((
        bindizr_config.api.listen_addr,
        bindizr_config.api.listen_port,
    ));

    // Bound here rather than inside the server so a taken port fails startup
    // instead of surfacing in a background task.
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| StartApiError::Bind { addr, source })?;

    let Some(certificate) = certificate else {
        log::info!("HTTP API server listening on http://{}", addr);
        let stop = shutdown.waiter();
        return Ok(tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, router::routes(cx))
                .with_graceful_shutdown(stop)
                .await
            {
                log::error!("API server error: {:?}", e);
            }
        }));
    };

    // The protocols axum-server's own loader offers.
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(certificate);
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls = RustlsConfig::from_config(Arc::new(server_config));
    let listener = listener.into_std().map_err(StartApiError::IntoStd)?;
    let server = axum_server::from_tcp_rustls(listener, tls)
        .map_err(|source| StartApiError::Serve { addr, source })?;

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
            .serve(router::routes(cx).into_make_service())
            .await
        {
            log::error!("API server error: {:?}", e);
        }
    }))
}
