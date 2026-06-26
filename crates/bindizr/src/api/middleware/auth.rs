use axum::{
    Json,
    body::Body,
    http::{Request, StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::{IntoResponse, Response},
};
use bindizr_core::log_debug;
use bindizr_service::auth::AuthService;
use serde_json::json;

pub(crate) async fn auth_middleware(
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract Authorization header
    let auth_header = match req.headers().get(AUTHORIZATION) {
        Some(header) => header,
        None => {
            return Ok(unauthorized("No authorization header"));
        }
    };

    // Extract Bearer token
    let auth_str = match auth_header.to_str() {
        Ok(s) => s,
        Err(_) => return Ok(unauthorized("Invalid authorization header")),
    };

    if !auth_str.starts_with("Bearer ") {
        return Ok(unauthorized("Invalid authentication scheme"));
    }

    let token = &auth_str[7..];

    // Validate token
    match AuthService::validate_token(token).await {
        Ok(api_token) => {
            req.extensions_mut().insert(api_token);
            Ok(next.run(req).await)
        }
        Err(err) => {
            log_debug!("Token validation error: {}", err);
            Ok(unauthorized("Invalid or expired token"))
        }
    }
}

fn unauthorized(message: &str) -> Response {
    let json_body = json!({ "error": message });
    (StatusCode::UNAUTHORIZED, Json(json_body)).into_response()
}
