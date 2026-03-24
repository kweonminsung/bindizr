use crate::{
    log_error,
    service::{error::ServiceError, token::TokenService},
    socket::dto::DaemonResponse,
};

pub async fn create_token(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let description = data.get("description").and_then(|v| v.as_str());
    let expires_in_days = data.get("expires_in_days").and_then(|v| v.as_i64());

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

pub async fn list_tokens() -> Result<DaemonResponse, String> {
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

pub async fn delete_token(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let token_id = data.get("id").and_then(|v| v.as_i64());

    if token_id.is_none() {
        return Err("Token ID is required".to_string());
    }

    let token_id = token_id.unwrap() as i32;

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
