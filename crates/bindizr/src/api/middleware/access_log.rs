//! Save answered management requests to the access log.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use bindizr_core::model::access_log::{AccessResult, AccessSource};
use bindizr_core::model::change::ChangeActor;
use bindizr_service::access::{AccessLogEntry, AccessLogErrorCode};
use bindizr_service::error::ErrorCode;
use bindizr_service::{Context, access};
use chrono::Utc;

/// The longest request path kept; a longer one is cut short, since an
/// unauthenticated client chooses it.
const MAX_TARGET_LEN: usize = 1024;

/// The longest method kept, the width of the MySQL and PostgreSQL column: an
/// extension method may be any length, and a longer one would fail the insert.
const MAX_METHOD_LEN: usize = 16;

/// Answer the request, then queue its row: the method and path, the peer, the
/// credential the auth layer verified, and its fixed error code.
/// Query, body, and client diagnostics stay out, since they may carry secrets.
pub(crate) async fn save_access_log(
    State(cx): State<Arc<Context>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let requested_at = Utc::now();
    // A method token and a URI path are ASCII, so any byte offset is a
    // character boundary.
    let method = request.method().as_str();
    let method = method[..method.len().min(MAX_METHOD_LEN)].to_string();
    let path = request.uri().path();
    let target = path[..path.len().min(MAX_TARGET_LEN)].to_string();

    let response = next.run(request).await;

    let status = response.status();
    let result = if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        AccessResult::Denied
    } else if status.is_client_error() || status.is_server_error() {
        AccessResult::Failed
    } else {
        AccessResult::Ok
    };

    access::save(
        &cx,
        AccessLogEntry {
            source: AccessSource::Api,
            // An IPv4-mapped peer of a dual-stack listener reads as IPv4.
            client_ip: peer.ip().to_canonical().to_string(),
            method,
            target,
            response_code: status.as_str().to_string(),
            result,
            actor: response.extensions().get::<ChangeActor>().cloned(),
            error_code: response
                .extensions()
                .get::<ErrorCode>()
                .copied()
                .map(AccessLogErrorCode::Service),
            requested_at,
        },
    );

    response
}
