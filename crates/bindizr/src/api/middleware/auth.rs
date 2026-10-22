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
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let Some(auth_header) = request.headers().get(AUTHORIZATION) else {
        return Ok(unauthorized("no authorization header"));
    };

    let Ok(auth_str) = auth_header.to_str() else {
        return Ok(unauthorized("invalid authorization header"));
    };

    let Some((scheme, credentials)) = auth_str.split_once(' ') else {
        return Ok(unauthorized("invalid authentication scheme"));
    };

    // RFC 9110, Sections 11.1 and 11.4: schemes ignore case; 1*SP separates credentials.
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Ok(unauthorized("invalid authentication scheme"));
    }

    let token = credentials.trim_start_matches(' ');

    match Caller::authenticate_token(&cx, token).await {
        Ok((caller, token)) => {
            request.extensions_mut().insert(caller);
            request.extensions_mut().insert(AuthenticatedToken(token));
            Ok(next.run(request).await)
        }
        Err(error) => {
            log::debug!("Token validation error: {}", error);
            Ok(ApiError::from(error).into_response())
        }
    }
}

/// Build the HTTP response for missing or invalid authentication.
fn unauthorized(message: &str) -> Response {
    ApiError(ServiceError::unauthorized(message)).into_response()
}
