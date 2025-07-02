use crate::{
    database::{get_api_token_repository, model::api_token::ApiToken},
    log_error,
};
use chrono::{DateTime, Utc};

pub struct AuthService;

impl AuthService {
    pub async fn validate_token(token_str: &str) -> Result<ApiToken, String> {
        let api_token_repository = get_api_token_repository();

        let stored_token = match api_token_repository.get_by_token(token_str).await {
            Ok(Some(token)) => token,
            Ok(None) => return Err("Invalid or expired token".to_string()),
            Err(e) => {
                log_error!("Failed to validate token: {}", e);
                return Err("Failed to validate token".to_string());
            }
        };

        // Check if the token is expired
        if let Some(expires_at) = &stored_token.expires_at {
            if Utc::now()
                > DateTime::parse_from_rfc3339(expires_at).map_err(|e| {
                    log_error!("Failed to parse expires_at: {}", e);
                    "Invalid expiration date format".to_string()
                })?
            {
                return Err("Token has expired".to_string());
            }
        }

        // Update last_used_at to current time
        let updated_token = api_token_repository
            .update(ApiToken {
                id: stored_token.id,
                token: stored_token.token,
                description: stored_token.description,
                expires_at: stored_token.expires_at,
                created_at: stored_token.created_at,
                last_used_at: Some(Utc::now().to_string()),
            })
            .await
            .map_err(|e| {
                log_error!("Failed to update last_used_at: {}", e);
                "Failed to update last_used_at".to_string()
            })?;

        Ok(updated_token)
    }
}
