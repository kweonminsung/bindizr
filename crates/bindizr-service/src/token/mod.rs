use chrono::{Duration, Utc};
use rand::{RngExt, distr::Alphanumeric};
use sha2::{Digest, Sha256};

use super::{error::ServiceError, repository::RepositoryService};
use crate::model::api_token::ApiToken;

/// Creates, lists, and revokes API tokens.
pub struct TokenService;

pub(crate) fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

impl TokenService {
    /// Create a new API token; the returned token carries the raw secret to show once.
    pub async fn create_token(
        description: Option<&str>,
        expires_in_days: Option<i64>,
    ) -> Result<ApiToken, ServiceError> {
        validate_expires_in_days(expires_in_days)?;

        let raw_token: String = rand::rng()
            .sample_iter(Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let token_hash = hash_token(&raw_token);

        let expires_at = expires_in_days.map(|days| Utc::now() + Duration::days(days));

        let mut created = RepositoryService::create_api_token(ApiToken {
            id: 0,
            token: token_hash,
            description: description.map(|d| d.to_string()),
            expires_at,
            created_at: Utc::now(),
            last_used_at: None,
        })
        .await?;

        created.token = raw_token;
        Ok(created)
    }

    /// List all API tokens with their secret hashes cleared.
    pub async fn list_tokens() -> Result<Vec<ApiToken>, ServiceError> {
        let mut tokens = RepositoryService::get_all_api_tokens().await?;
        for token in &mut tokens {
            token.token.clear();
        }
        Ok(tokens)
    }

    /// Delete the API token with the given id, returning `NotFound` if it is absent.
    pub async fn delete_token(token_id: i32) -> Result<(), ServiceError> {
        let exists = RepositoryService::get_api_token_by_id(token_id).await?;
        if exists.is_none() {
            return Err(ServiceError::token_not_found());
        }

        RepositoryService::delete_api_token(token_id).await
    }
}

fn validate_expires_in_days(expires_in_days: Option<i64>) -> Result<(), ServiceError> {
    if let Some(days) = expires_in_days
        && days <= 0
    {
        return Err(ServiceError::invalid_input(
            "expires_in_days must be greater than 0",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests;
