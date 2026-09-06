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
    /// Create an API token; the secret comes back beside it, shown this once.
    pub async fn create(
        caller: &Caller,
        name: &str,
        description: Option<&str>,
        expires_in_days: Option<i64>,
        is_global: bool,
    ) -> Result<(ApiToken, String), ServiceError> {
        caller.require_global("manage API tokens")?;

        let name = normalize_token_name(name)?;
        validate_token_description(description)?;
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

        let created = RepositoryService::create_api_token(ApiToken {
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

        Ok((created, raw_token))
    }

    /// List all API tokens.
    pub async fn list(caller: &Caller) -> Result<Vec<ApiToken>, ServiceError> {
        caller.require_global("manage API tokens")?;

        RepositoryService::list_api_tokens().await
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

/// Lowercased so one name means one token on every backend (MySQL compares
/// case-insensitively), and kept to one URL path segment for `/tokens/{name}`.
pub(crate) fn normalize_token_name(name: &str) -> Result<String, ServiceError> {
    let name = name.trim().to_lowercase();

    if name.is_empty() {
        return Err(ServiceError::invalid_input("token name must not be empty"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(ServiceError::invalid_input(
            "token name may contain only letters, digits, '.', '_', and '-'",
        ));
    }
    // Dot segments get normalized away; `self` is the lookup route.
    if name == "." || name == ".." || name == "self" {
        return Err(ServiceError::invalid_input(format!(
            "token name must not be '{name}'"
        )));
    }
    if name.len() > MAX_TOKEN_NAME_LEN {
        return Err(ServiceError::invalid_input(
            "token name must be 255 bytes or fewer",
        ));
    }

    Ok(name)
}

/// VARCHAR(255) counts characters, not bytes, and PostgreSQL text cannot hold
/// NUL; both must be 400s rather than a backend-dependent insert failure.
fn validate_token_description(description: Option<&str>) -> Result<(), ServiceError> {
    let Some(description) = description else {
        return Ok(());
    };
    if description.chars().count() > MAX_TOKEN_DESCRIPTION_LEN {
        return Err(ServiceError::invalid_input(
            "description must be 255 characters or fewer",
        ));
    }
    if description.contains('\0') {
        return Err(ServiceError::invalid_input(
            "description must not contain NUL characters",
        ));
    }
    Ok(())
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
