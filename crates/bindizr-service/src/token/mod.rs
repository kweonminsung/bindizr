use bindizr_core::dns::name::has_whitespace_or_control;
use chrono::{DateTime, Duration, Utc};
use rand::{RngExt, distr::Alphanumeric};
use sha2::{Digest, Sha256};

use super::{error::ServiceError, repository::RepositoryService};
use crate::{authorization::Caller, model::api_token::ApiToken};

const MAX_TOKEN_NAME_LEN: usize = 255;
/// `api_tokens.description` is VARCHAR(255) on MySQL and PostgreSQL.
const MAX_TOKEN_DESCRIPTION_LEN: usize = 255;
/// A century: inside every backend's timestamp range (MySQL DATETIME ends at 9999).
const MAX_EXPIRES_IN_DAYS: i64 = 36_500;

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
    pub async fn create(
        caller: &Caller,
        name: &str,
        description: Option<&str>,
        expires_in_days: Option<i64>,
        is_global: bool,
    ) -> Result<ApiToken, ServiceError> {
        caller.require_global("manage API tokens")?;

        let name = normalize_token_name(name)?;
        if description.is_some_and(|d| d.len() > MAX_TOKEN_DESCRIPTION_LEN) {
            return Err(ServiceError::invalid_input(
                "description must be 255 bytes or fewer",
            ));
        }
        let expires_at = expires_at(expires_in_days)?;

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
    pub async fn list(caller: &Caller) -> Result<Vec<ApiToken>, ServiceError> {
        caller.require_global("manage API tokens")?;

        let mut tokens = RepositoryService::list_api_tokens().await?;
        for token in &mut tokens {
            token.token.clear();
        }
        Ok(tokens)
    }

    /// Delete the API token with the given name, returning `NotFound` if it
    /// is absent.
    pub async fn delete(caller: &Caller, name: &str) -> Result<(), ServiceError> {
        caller.require_global("manage API tokens")?;

        let token = Self::lookup_by_name(name).await?;

        RepositoryService::delete_api_token(token.id).await
    }

    pub(crate) async fn lookup_by_name(name: &str) -> Result<ApiToken, ServiceError> {
        RepositoryService::get_api_token_by_name(&normalize_token_name(name)?)
            .await?
            .ok_or_else(|| ServiceError::token_not_found(name))
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

/// When a token created now expires; `None` never does.
fn expires_at(expires_in_days: Option<i64>) -> Result<Option<DateTime<Utc>>, ServiceError> {
    let Some(days) = expires_in_days else {
        return Ok(None);
    };
    if !(1..=MAX_EXPIRES_IN_DAYS).contains(&days) {
        return Err(ServiceError::invalid_input(format!(
            "expires_in_days must be between 1 and {MAX_EXPIRES_IN_DAYS}"
        )));
    }
    // Within the cap neither the duration nor the date can overflow.
    Ok(Some(Utc::now() + Duration::days(days)))
}

pub mod grant;

#[cfg(test)]
mod tests;
