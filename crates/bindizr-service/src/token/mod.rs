use chrono::{DateTime, Duration, Utc};
use rand::{RngExt, distr::Alphanumeric};
use sha2::{Digest, Sha256};

use super::{error::ServiceError, repository::RepositoryService};
use crate::{
    authorization::Caller,
    model::api_token::ApiToken,
    text::{MAX_COLUMN_TEXT_LEN, normalize_description, normalize_identifier},
    types::{GetTokenResponse, PageFilter, PaginatedResponse},
};

/// A century: inside every backend's timestamp range (MySQL DATETIME ends at 9999).
const MAX_EXPIRES_IN_DAYS: i64 = 36_500;

/// Creates, lists, and revokes API tokens.
pub struct TokenService;

/// Hash an API token for storage and lookup.
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
        caller.authorize_global("manage API tokens")?;

        let name = normalize_token_name(name)?;
        let description = normalize_description(description, ServiceError::invalid_input)?;
        let expires_at = normalize_expires_at(expires_in_days)?;

        // Friendly pre-check; the UNIQUE(name) backstop covers the race.
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
            description,
            is_global,
            expires_at,
            created_at: Utc::now(),
            last_used_at: None,
        })
        .await?;

        Ok((created, raw_token))
    }

    /// List all API tokens.
    pub async fn list(
        caller: &Caller,
        page: PageFilter,
    ) -> Result<PaginatedResponse<GetTokenResponse>, ServiceError> {
        caller.authorize_global("manage API tokens")?;

        let tokens = RepositoryService::list_api_tokens().await?;
        PaginatedResponse::from_collection(
            tokens.iter().map(GetTokenResponse::from_token).collect(),
            page.limit,
            page.offset,
        )
    }

    /// Create `secret` as a global token named `initial`. The daemon calls
    /// this only on the startup that built the schema, so a token revoked
    /// later is never seeded back, and passes a secret the config reader
    /// Every API token, for the daemon's startup hint.
    pub async fn count_all() -> Result<u64, ServiceError> {
        Ok(RepositoryService::list_api_tokens().await?.len() as u64)
    }

    /// Delete the API token with the given name, returning `NotFound` if it
    /// is absent.
    pub async fn delete(caller: &Caller, name: &str) -> Result<(), ServiceError> {
        caller.authorize_global("manage API tokens")?;

        let token = Self::lookup_by_name(name).await?;

        RepositoryService::delete_api_token(token.id).await
    }

    /// Load an API token by name or return a not-found error.
    pub(crate) async fn lookup_by_name(name: &str) -> Result<ApiToken, ServiceError> {
        RepositoryService::get_api_token_by_name(&normalize_token_name(name)?)
            .await?
            .ok_or_else(|| ServiceError::token_not_found(name))
    }
}

/// Lowercased so one name means one token on every backend (MySQL compares
/// case-insensitively), and kept to one URL path segment for `/tokens/{name}`.
pub(crate) fn normalize_token_name(name: &str) -> Result<String, ServiceError> {
    let name = normalize_identifier(name, "token name", MAX_COLUMN_TEXT_LEN)?;
    // Dot segments get normalized away; `self` is the lookup route.
    if name == "." || name == ".." || name == "self" {
        return Err(ServiceError::invalid_input(format!(
            "token name must not be '{name}'"
        )));
    }
    Ok(name)
}

/// When a token created now expires; `None` never does.
fn normalize_expires_at(
    expires_in_days: Option<i64>,
) -> Result<Option<DateTime<Utc>>, ServiceError> {
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
