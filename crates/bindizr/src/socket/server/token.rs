use bindizr_core::log_error;
use bindizr_service::{error::ServiceError, token::TokenService};
use serde::Deserialize;

use crate::socket::{server::parse_params, types::DaemonResponse};

#[derive(Deserialize)]
struct CreateTokenParams {
    description: Option<String>,
    expires_in_days: Option<i64>,
}

#[derive(Deserialize)]
struct DeleteTokenParams {
    id: i32,
}

/// Handle the `TokenCreate` command by creating a new API token.
pub(super) async fn create_token(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: CreateTokenParams = parse_params(data)?;

    let created_token =
        TokenService::create_token(params.description.as_deref(), params.expires_in_days).await?;

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
    let params: DeleteTokenParams = parse_params(data)?;

    if params.id < 0 {
        return Err(ServiceError::invalid_input("Token ID must be non-negative"));
    }

    TokenService::delete_token(params.id).await?;

    let response = DaemonResponse {
        message: "Token deleted successfully".to_string(),
        data: serde_json::Value::Null,
    };
    Ok(response)
}
