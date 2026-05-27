use crate::{
    log_error,
    service::{error::ServiceError, token::TokenService},
    socket::types::DaemonResponse,
};

pub(super) async fn create_token(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let description = data.get("description").and_then(|v| v.as_str());
    let expires_in_days = data.get("expires_in_days").and_then(|v| v.as_i64());

    // Create token
    let created_token = TokenService::create_token(description, expires_in_days)
        .await
        .map_err(|e| e.to_string())?;

    // Create response
    let response = DaemonResponse {
        message: "Token created successfully".to_string(),
        data: serde_json::to_value(created_token).unwrap(),
    };
    Ok(response)
}

pub(super) async fn list_tokens() -> Result<DaemonResponse, String> {
    // List tokens
    let tokens = match TokenService::list_tokens().await {
        Ok(tokens) => Ok(tokens),
        Err(e) => {
            log_error!("Failed to list tokens: {}", e);
            Err("Failed to list tokens".to_string())
        }
    }?;

    let response = DaemonResponse {
        message: "Tokens retrieved successfully".to_string(),
        data: serde_json::to_value(tokens).unwrap(),
    };
    Ok(response)
}

pub(super) async fn delete_token(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let token_id_i64 = data
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| "Token ID is required".to_string())?;

    let token_id =
        i32::try_from(token_id_i64).map_err(|_| "Token ID is out of range".to_string())?;

    if token_id < 0 {
        return Err("Token ID must be non-negative".to_string());
    }

    TokenService::delete_token(token_id)
        .await
        .map_err(|e| match e {
            ServiceError::NotFound(msg) => msg,
            _ => format!("Failed to delete token: {}", e),
        })?;

    let response = DaemonResponse {
        message: "Token deleted successfully".to_string(),
        data: serde_json::Value::Null,
    };
    Ok(response)
}
