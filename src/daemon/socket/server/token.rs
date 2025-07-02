use chrono::{Duration, Utc};
use rand::{Rng, distributions::Alphanumeric};
use sha2::{Digest, Sha256};

use crate::{
    daemon::socket::dto::DaemonResponse,
    database::{get_api_token_repository, model::api_token::ApiToken},
    log_error,
};

pub async fn create_token(data: &serde_json::Value) -> Result<DaemonResponse, String> {
    let description = data.get("description").and_then(|v| v.as_str());
    let expires_in_days = data.get("expires_in_days").and_then(|v| v.as_i64());

    // Generate random token (32 bytes)
    let random_string: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // SHA-256 hashing
    let mut hasher = Sha256::new();
    hasher.update(random_string);
    let token = hex::encode(hasher.finalize());

    let expires_at = expires_in_days.map(|days| Utc::now() + Duration::days(days));

    // Create token
    let api_token_repository = get_api_token_repository();
    let created_token = api_token_repository
        .create(ApiToken {
            id: 0, // Will be set by the database
            token: token,
            description: description.map(|d| d.to_string()),
            expires_at: expires_at,
            created_at: Utc::now(), // Will be set by the database
            last_used_at: None,
        })
        .await
        .map_err(|e| format!("Failed to create token: {}", e))?;

    // Create response
    let response = DaemonResponse {
        message: "Token created successfully".to_string(),
        data: serde_json::to_value(created_token).unwrap(),
    };
    Ok(response)
}

pub async fn list_tokens() -> Result<DaemonResponse, String> {
    let api_token_repository = get_api_token_repository();

    // List tokens
    let tokens = match api_token_repository.get_all().await {
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

    let api_token_repository = get_api_token_repository();

    // Check if token exists
    match api_token_repository.get_by_id(token_id).await {
        Ok(Some(_)) => (),
        Ok(None) => return Err("Token not found".to_string()),
        Err(e) => {
            log_error!("Failed to fetch token by ID: {}", e);
            return Err("Failed to fetch token by ID".to_string());
        }
    }

    // Delete token
    api_token_repository
        .delete(token_id)
        .await
        .map_err(|e| format!("Failed to delete token: {}", e))?;

    let response = DaemonResponse {
        message: "Token deleted successfully".to_string(),
        data: serde_json::Value::Null,
    };
    Ok(response)
}
