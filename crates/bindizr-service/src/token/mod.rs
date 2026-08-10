use bindizr_core::dns::name::has_whitespace_or_control;
use chrono::{Duration, Utc};
use rand::{RngExt, distr::Alphanumeric};
use sha2::{Digest, Sha256};

use super::{error::ServiceError, repository::RepositoryService};
use crate::{authorization::Caller, model::api_token::ApiToken};

const MAX_TOKEN_NAME_LEN: usize = 255;

/// Creates, lists, and revokes API tokens.
pub struct TokenService;

pub(crate) fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

impl TokenService {
    /// Create a new API token; the returned token carries the raw secret to
    /// show once.
    pub async fn create_token(
        caller: &Caller,
        name: &str,
        description: Option<&str>,
        expires_in_days: Option<i64>,
        is_global: bool,
    ) -> Result<ApiToken, ServiceError> {
        caller.require_global("manage API tokens")?;

        let name = normalize_token_name(name)?;
        validate_expires_in_days(expires_in_days)?;

        if RepositoryService::get_api_token_by_name(&name)
            .await?
            .is_some()
        {
            return Err(ServiceError::token_conflict(&name));
        }

        let raw_token: String = rand::rng()
            .sample_iter(Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let token_hash = hash_token(&raw_token);

        let expires_at = expires_in_days.map(|days| Utc::now() + Duration::days(days));

        let mut created = RepositoryService::create_api_token(ApiToken {
            id: 0,
            name,
            token: token_hash,
            description: description.map(|d| d.to_string()),
            is_global,
            expires_at,
            created_at: Utc::now(),
            last_used_at: None,
        })
        .await?;

        created.token = raw_token;
        Ok(created)
    }

    /// List all API tokens with their secret hashes cleared.
    pub async fn list_tokens(caller: &Caller) -> Result<Vec<ApiToken>, ServiceError> {
        caller.require_global("manage API tokens")?;

        let mut tokens = RepositoryService::get_all_api_tokens().await?;
        for token in &mut tokens {
            token.token.clear();
        }
        Ok(tokens)
    }

    /// Delete the API token with the given name, returning `NotFound` if it
    /// is absent.
    pub async fn delete_token(caller: &Caller, name: &str) -> Result<(), ServiceError> {
        caller.require_global("manage API tokens")?;

        let token = RepositoryService::get_api_token_by_name(&normalize_token_name(name)?)
            .await?
            .ok_or_else(|| ServiceError::token_not_found(name))?;

        RepositoryService::delete_api_token(token.id).await
    }
}

/// Lowercased so one name means one token on every backend: MySQL compares the
/// column case-insensitively, the others exactly.
pub(crate) fn normalize_token_name(name: &str) -> Result<String, ServiceError> {
    let name = name.trim().to_lowercase();

    if name.is_empty() {
        return Err(ServiceError::invalid_input("token name must not be empty"));
    }
    if has_whitespace_or_control(&name) {
        return Err(ServiceError::invalid_input(
            "token name must not contain whitespace or control characters",
        ));
    }
    if name.len() > MAX_TOKEN_NAME_LEN {
        return Err(ServiceError::invalid_input(
            "token name must be 255 bytes or fewer",
        ));
    }

    Ok(name)
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
