use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::{IntoResponse, Response},
};
use bindizr_service::{Context, authorization::Caller, error::ServiceError};

use crate::api::{AuthenticatedToken, error::ApiError};

/// Validate the request's Bearer token, rejecting unauthorized requests.
pub(crate) async fn auth_middleware(
    State(cx): State<Arc<Context>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = match req.headers().get(AUTHORIZATION) {
        Some(header) => header,
        None => {
            return Ok(unauthorized("no authorization header"));
        }
    };

    let auth_str = match auth_header.to_str() {
        Ok(s) => s,
        Err(_) => return Ok(unauthorized("invalid authorization header")),
    };

    if !auth_str.starts_with("Bearer ") {
        return Ok(unauthorized("invalid authentication scheme"));
    }

    let token = &auth_str[7..];

    match Caller::authenticate(&cx, token).await {
        Ok((caller, token)) => {
            req.extensions_mut().insert(caller);
            req.extensions_mut().insert(AuthenticatedToken(token));
            Ok(next.run(req).await)
        }
        Err(err) => {
            log::debug!("Token validation error: {}", err);
            Ok(ApiError::from(err).into_response())
        }
    }
}

/// Build the HTTP response for missing or invalid authentication.
fn unauthorized(message: &str) -> Response {
    ApiError(ServiceError::unauthorized(message)).into_response()
}
