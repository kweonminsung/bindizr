//! Creates, lists, and revokes API tokens.

use bindizr_core::model::api_token::TokenId;
use chrono::{DateTime, Duration, Utc};
use rand::{RngExt, distr::Alphanumeric};
use ring::digest::{SHA256, digest};

use super::error::ServiceError;
use crate::{
    Context,
    authorization::Caller,
    model::api_token::ApiToken,
    text::{MAX_COLUMN_TEXT_LEN, normalize_description, normalize_identifier},
    types::{CreateTokenRequest, GetTokenResponse, PageFilter, PaginatedResponse, build_page},
};

/// A century: inside every backend's timestamp range (MySQL DATETIME ends at 9999).
const MAX_EXPIRES_IN_DAYS: i64 = 36_500;

/// Hash an API token for storage and lookup.
pub(crate) fn hash_token(token: &str) -> String {
    hex::encode(digest(&SHA256, token.as_bytes()))
}

/// Create an API token; the secret comes back beside it, shown this once.
pub async fn create(
    cx: &Context,
    caller: &Caller,
    request: &CreateTokenRequest,
) -> Result<(ApiToken, String), ServiceError> {
    caller.authorize_global("manage API tokens")?;

    let name = normalize_token_name(&request.name)?;
    let description =
        normalize_description(request.description.as_deref(), ServiceError::invalid_input)?;
    let expires_at = normalize_expires_at(request.expires_in_days)?;

    // Friendly pre-check; the UNIQUE(name) backstop covers the race.
    if bindizr_db::api_token::get_by_name(cx.db(), &name)
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

    let created = bindizr_db::api_token::create(
        cx.db(),
        ApiToken {
            id: TokenId::UNWRITTEN,
            name: name.clone(),
            token: token_hash,
            description,
            is_global: request.global,
            expires_at,
            created_at: Utc::now(),
            last_used_at: None,
        },
    )
    .await
    .map_err(|e| {
        // A create that raced past the pre-check trips UNIQUE(name); the
        // backstop reads as the same conflict.
        if e.is_unique_violation() {
            ServiceError::token_conflict(&name)
        } else {
            e.into()
        }
    })?;

    Ok((created, raw_token))
}

/// List all API tokens.
pub async fn list(
    cx: &Context,
    caller: &Caller,
    page: PageFilter,
) -> Result<PaginatedResponse<GetTokenResponse>, ServiceError> {
    caller.authorize_global("manage API tokens")?;

    let tokens = bindizr_db::api_token::list_all(cx.db()).await?;
    build_page(
        tokens.iter().map(GetTokenResponse::from).collect(),
        page.limit,
        page.offset,
    )
}

/// The number of API tokens, read for the daemon's startup hint.
pub async fn count_all(cx: &Context) -> Result<u64, ServiceError> {
    Ok(bindizr_db::api_token::list_all(cx.db()).await?.len() as u64)
}

/// Delete the API token with the given name, returning `NotFound` if it
/// is absent.
pub async fn delete(cx: &Context, caller: &Caller, name: &str) -> Result<(), ServiceError> {
    caller.authorize_global("manage API tokens")?;

    let token = lookup_by_name(cx, name).await?;

    Ok(bindizr_db::api_token::delete(cx.db(), token.id).await?)
}

/// Load an API token by name or return a not-found error.
pub(crate) async fn lookup_by_name(cx: &Context, name: &str) -> Result<ApiToken, ServiceError> {
    bindizr_db::api_token::get_by_name(cx.db(), &normalize_token_name(name)?)
        .await?
        .ok_or_else(|| ServiceError::token_not_found(name))
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
