//! API token authentication.

use chrono::{Duration, Utc};

use super::{repository::RepositoryService, token::hash_token};
use crate::{error::ServiceError, log_error, model::api_token::ApiToken};

/// How long a `last_used_at` stamp stays fresh; stamping every request would
/// put a database write on the hot path for no added precision.
const LAST_USED_STAMP_INTERVAL_SECS: i64 = 60;

/// Authenticates API tokens.
pub struct AuthService;

impl AuthService {
    /// Validate an API token, rejecting expired tokens and stamping `last_used_at`.
    pub async fn validate_token(token_str: &str) -> Result<ApiToken, ServiceError> {
        let token_hash = hash_token(token_str);
        let stored_token = match RepositoryService::get_api_token_by_token(&token_hash).await {
            Ok(Some(token)) => token,
            Ok(None) => {
                return Err(ServiceError::invalid_token(
                    "Invalid or expired token".to_string(),
                ));
            }
            Err(e) => {
                log_error!("Failed to validate token: {}", e);
                return Err(ServiceError::internal(
                    "Failed to validate token".to_string(),
                ));
            }
        };

        if let Some(expires_at) = &stored_token.expires_at
            && Utc::now() >= *expires_at
        {
            return Err(ServiceError::invalid_token("Token has expired".to_string()));
        }

        let stamp_is_fresh = stored_token.last_used_at.is_some_and(|last_used| {
            Utc::now() - last_used < Duration::seconds(LAST_USED_STAMP_INTERVAL_SECS)
        });
        if stamp_is_fresh {
            return Ok(stored_token);
        }

        let updated_token = RepositoryService::update_api_token(ApiToken {
            id: stored_token.id,
            name: stored_token.name,
            token: stored_token.token,
            description: stored_token.description,
            is_global: stored_token.is_global,
            expires_at: stored_token.expires_at,
            created_at: stored_token.created_at,
            last_used_at: Some(Utc::now()),
        })
        .await
        .map_err(|e| {
            log_error!("Failed to update last_used_at: {}", e);
            ServiceError::internal("Failed to update last_used_at".to_string())
        })?;

        Ok(updated_token)
    }
}
