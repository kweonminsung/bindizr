use crate::{
    api::service::auth::AuthService, daemon::socket::dto::DaemonResponse, database::DATABASE_POOL,
};

pub fn create_token(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let description = data.get("description").and_then(|v| v.as_str());
    let expires_in_days = data.get("expires_in_days").and_then(|v| v.as_i64());

    // Generate token
    let token = AuthService::generate_token(&DATABASE_POOL, description, expires_in_days)?;

    // Create response
    let response = DaemonResponse {
        message: "Token created successfully".to_string(),
        data: serde_json::to_value(token).unwrap(),
    };
    Ok(response)
}

pub fn list_tokens() -> Result<DaemonResponse, String> {
    let tokens = AuthService::list_tokens(&DATABASE_POOL)
        .map_err(|e| format!("Failed to list tokens: {}", e))?;

    let response = DaemonResponse {
        message: "Tokens retrieved successfully".to_string(),
        data: serde_json::to_value(tokens).unwrap(),
    };
    Ok(response)
}

pub fn delete_token(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let token_id = data.get("id").and_then(|v| v.as_i64());

    if token_id.is_none() {
        return Err("Token ID is required".to_string());
    }

    let token_id = token_id.unwrap() as i32;

    AuthService::delete_token(&DATABASE_POOL, token_id)
        .map_err(|e| format!("Failed to delete token: {}", e))?;

    let response = DaemonResponse {
        message: "Token deleted successfully".to_string(),
        data: serde_json::Value::Null,
    };
    Ok(response)
}
