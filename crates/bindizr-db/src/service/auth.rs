use crate::{database::model::api_token::ApiToken, log_error, service::error::ServiceError};
use chrono::Utc;

use super::{repository::RepositoryService, token::hash_token};

pub struct AuthService;

impl AuthService {
    pub async fn validate_token(token_str: &str) -> Result<ApiToken, ServiceError> {
        let token_hash = hash_token(token_str);
        let stored_token = match RepositoryService::get_api_token_by_token(&token_hash).await {
            Ok(Some(token)) => token,
            Ok(None) => {
                return Err(ServiceError::Unauthorized(
                    "Invalid or expired token".to_string(),
                ));
            }
            Err(e) => {
                log_error!("Failed to validate token: {}", e);
                return Err(ServiceError::Internal(
                    "Failed to validate token".to_string(),
                ));
            }
        };

        // Check if the token is expired
        if let Some(expires_at) = &stored_token.expires_at
            && Utc::now() >= *expires_at
        {
            return Err(ServiceError::Unauthorized("Token has expired".to_string()));
        }

        // Update last_used_at to current time
        let updated_token = RepositoryService::update_api_token(ApiToken {
            id: stored_token.id,
            token: stored_token.token,
            description: stored_token.description,
            expires_at: stored_token.expires_at,
            created_at: stored_token.created_at,
            last_used_at: Some(Utc::now()),
        })
        .await
        .map_err(|e| {
            log_error!("Failed to update last_used_at: {}", e);
            ServiceError::Internal("Failed to update last_used_at".to_string())
        })?;

        Ok(updated_token)
    }
}
