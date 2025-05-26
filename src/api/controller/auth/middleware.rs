use super::AuthService;
use crate::api::controller::internal::{utils, Request, Response, StatusCode};
use crate::{config, database::DATABASE_POOL};
use serde_json::json;

pub async fn auth_middleware(request: Request) -> Result<Request, Response> {
    // Check if authentication is required
    if !config::get_config("api.require_authentication")
        .parse::<bool>()
        .unwrap_or(false)
    {
        return Ok(request);
    }

    // Extract Authorization header
    let auth_header = match request.headers().get(hyper::header::AUTHORIZATION) {
        Some(header) => header,
        None => {
            return Err(utils::json_response(
                json!({ "error": "No authorization header" }),
                StatusCode::UNAUTHORIZED,
            ))
        }
    };

    // Extract Bearer token
    let auth_str = match auth_header.to_str() {
        Ok(s) => s,
        Err(_) => {
            return Err(utils::json_response(
                json!({ "error": "Invalid authorization header" }),
                StatusCode::UNAUTHORIZED,
            ))
        }
    };
    if !auth_str.starts_with("Bearer ") {
        return Err(utils::json_response(
            json!({ "error": "Invalid authentication scheme" }),
            StatusCode::UNAUTHORIZED,
        ));
    }

    let token = &auth_str[7..];

    // Validate token
    match AuthService::validate_token(&DATABASE_POOL, token) {
        Ok(api_token) => {
            // Save token information in request extensions
            let mut request = request;
            request.extensions_mut().insert(api_token);
            Ok(request)
        }
        Err(err) => {
            eprintln!("Token validation error: {}", err);
            return Err(utils::json_response(
                json!({ "error": "Invalid or expired token" }),
                StatusCode::UNAUTHORIZED,
            ));
        }
    }
}
