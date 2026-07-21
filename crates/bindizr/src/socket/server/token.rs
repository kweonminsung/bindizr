use bindizr_core::log_error;
use bindizr_service::{error::ServiceError, token::TokenService};

use crate::socket::types::DaemonResponse;

/// Handle the `TokenCreate` command by creating a new API token.
pub(super) async fn create_token(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let description = data.get("description").and_then(|v| v.as_str());
    let expires_in_days = data.get("expires_in_days").and_then(|v| v.as_i64());

    let created_token = TokenService::create_token(description, expires_in_days).await?;

    let response = DaemonResponse {
        message: "Token created successfully".to_string(),
        data: serde_json::to_value(created_token)
            .map_err(|e| ServiceError::internal(format!("Failed to serialize response: {}", e)))?,
    };
    Ok(response)
}

/// Handle the `TokenList` command by returning all API tokens.
pub(super) async fn list_tokens() -> Result<DaemonResponse, ServiceError> {
    let tokens = match TokenService::list_tokens().await {
        Ok(tokens) => tokens,
        Err(e) => {
            log_error!("Failed to list tokens: {}", e);
            return Err(ServiceError::internal("Failed to list tokens"));
        }
    };

    let response = DaemonResponse {
        message: "Tokens retrieved successfully".to_string(),
        data: serde_json::to_value(tokens)
            .map_err(|e| ServiceError::internal(format!("Failed to serialize response: {}", e)))?,
    };
    Ok(response)
}

/// Handle the `TokenDelete` command by deleting an API token by ID.
pub(super) async fn delete_token(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let token_id_i64 = data
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| ServiceError::invalid_input("Token ID is required"))?;

    let token_id = i32::try_from(token_id_i64)
        .map_err(|_| ServiceError::invalid_input("Token ID is out of range"))?;

    if token_id < 0 {
        return Err(ServiceError::invalid_input("Token ID must be non-negative"));
    }

    TokenService::delete_token(token_id).await?;

    let response = DaemonResponse {
        message: "Token deleted successfully".to_string(),
        data: serde_json::Value::Null,
    };
    Ok(response)
}
