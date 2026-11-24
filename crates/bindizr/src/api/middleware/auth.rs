use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use bindizr_core::model::change::ChangeActor;
use bindizr_service::Context;
use bindizr_service::authorization::Caller;
use bindizr_service::error::ServiceError;

use crate::api::error::ApiError;
use crate::api::extract::AuthenticatedToken;

/// Validate the request's Bearer token, rejecting unauthorized requests.
pub(crate) async fn auth_middleware(
    State(cx): State<Arc<Context>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let Some(auth_header) = request.headers().get(AUTHORIZATION) else {
        return unauthorized("no authorization header");
    };

    let Ok(auth_str) = auth_header.to_str() else {
        return unauthorized("invalid authorization header");
    };

    let Some((scheme, credentials)) = auth_str.split_once(' ') else {
        return unauthorized("invalid authentication scheme");
    };

    // RFC 9110, Sections 11.1 and 11.4: schemes ignore case; 1*SP separates credentials.
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return unauthorized("invalid authentication scheme");
    }

    let token = credentials.trim_start_matches(' ');

    match Caller::authenticate_token(&cx, token).await {
        Ok((caller, token)) => {
            // The response names the token for the access log, which sees it alone.
            let actor = ChangeActor::Token {
                name: token.name.clone(),
            };
            request.extensions_mut().insert(caller);
            request.extensions_mut().insert(AuthenticatedToken(token));

            let mut response = next.run(request).await;
            response.extensions_mut().insert(actor);
            response
        }
        Err(error) => {
            log::debug!("Token validation error: {error}");
            ApiError::from(error).into_response()
        }
    }
}

/// Build the HTTP response for missing or invalid authentication.
fn unauthorized(message: &str) -> Response {
    ApiError::from(ServiceError::unauthorized(message)).into_response()
}
