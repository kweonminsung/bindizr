//! Creates, lists, and revokes API tokens.

use std::collections::HashMap;

use bindizr_core::model::{api_token::TokenId, role::RoleId, role_grant::Action};
use chrono::{DateTime, Duration, Utc};
use rand::{RngExt, distr::Alphanumeric};
use ring::digest::{SHA256, digest};

use super::error::ServiceError;
use crate::{
    Context,
    authorization::Caller,
    model::api_token::ApiToken,
    pagination::build_page,
    role,
    text::{MAX_COLUMN_TEXT_LEN, normalize_description, normalize_identifier},
    types::{CreateTokenRequest, GetTokenResponse, PaginatedResponse, TokenFilter},
};

/// A century: inside every backend's timestamp range (MySQL DATETIME ends at 9999).
const MAX_EXPIRES_IN_DAYS: i64 = 36_500;

/// Hash an API token for storage and lookup.
pub(crate) fn hash_token(token: &str) -> String {
    hex::encode(digest(&SHA256, token.as_bytes()))
}

/// Create an API token in the request's role; the secret is shown this once.
pub async fn create(
    cx: &Context,
    caller: &Caller,
    request: &CreateTokenRequest,
) -> Result<(GetTokenResponse, String), ServiceError> {
    caller.authorize_action(Action::AccessManage)?;

    let name = normalize_token_name(&request.name)?;
    let role = role::lookup_by_name(cx, &request.role_name).await?;
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
            role_id: role.id,
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
        } else if e.is_foreign_key_violation() {
            ServiceError::role_not_found(&role.name)
        } else {
            e.into()
        }
    })?;

    Ok((
        GetTokenResponse::from_token(&created, &role.name),
        raw_token,
    ))
}

/// List the API tokens, every one or one role's.
pub async fn list(
    cx: &Context,
    caller: &Caller,
    filter: &TokenFilter,
) -> Result<PaginatedResponse<GetTokenResponse>, ServiceError> {
    caller.authorize_action(Action::AccessManage)?;

    let tokens = match &filter.role_name {
        Some(role_name) => {
            let role = role::lookup_by_name(cx, role_name).await?;
            bindizr_db::api_token::list_by_role_id(cx.db(), role.id).await?
        }
        None => bindizr_db::api_token::list_all(cx.db()).await?,
    };
    let role_names: HashMap<RoleId, String> = bindizr_db::role::list_all(cx.db())
        .await?
        .into_iter()
        .map(|role| (role.id, role.name))
        .collect();
    build_page(
        tokens
            .iter()
            .map(|token| {
                let role_name = role_names.get(&token.role_id).map_or("", String::as_str);
                GetTokenResponse::from_token(token, role_name)
            })
            .collect(),
        filter.limit,
        filter.offset,
    )
}

/// Describe `token` with its role's name; any token may read itself.
pub async fn get_self(cx: &Context, token: &ApiToken) -> Result<GetTokenResponse, ServiceError> {
    let role = bindizr_db::role::get(cx.db(), token.role_id)
        .await?
        .ok_or_else(|| ServiceError::role_not_found(token.role_id))?;
    Ok(GetTokenResponse::from_token(token, &role.name))
}

/// The number of API tokens, read for the daemon's startup hint.
pub async fn count_all(cx: &Context) -> Result<u64, ServiceError> {
    Ok(bindizr_db::api_token::list_all(cx.db()).await?.len() as u64)
}

/// Delete the API token with the given name, returning `NotFound` if it
/// is absent.
pub async fn delete(cx: &Context, caller: &Caller, name: &str) -> Result<(), ServiceError> {
    caller.authorize_action(Action::AccessManage)?;

    let token = lookup_by_name(cx, name).await?;

    Ok(bindizr_db::api_token::delete(cx.db(), token.id).await?)
}

/// Load an API token by name or return a not-found error.
async fn lookup_by_name(cx: &Context, name: &str) -> Result<ApiToken, ServiceError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    /// Verify that `normalize_token_name` trims and folds case.
    #[test]
    fn normalize_token_name_trims_and_folds_case() {
        assert_eq!(
            normalize_token_name(" external-dns ").unwrap(),
            "external-dns"
        );
        assert_eq!(normalize_token_name("Deploy").unwrap(), "deploy");
        assert_eq!(
            normalize_token_name("DEPLOY").unwrap(),
            normalize_token_name("deploy").unwrap()
        );
    }

    /// Verify that `normalize_token_name` rejects empty and whitespace names.
    #[test]
    fn normalize_token_name_rejects_empty_and_whitespace_names() {
        for name in ["", "   ", "bad name", "bad\tname"] {
            let err = normalize_token_name(name).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidInput);
        }
    }

    /// Verify rejection of token names that cannot remain one URL path segment.
    ///
    /// `/` splits segments, `?` and `#` terminate them, and URL normalization removes dot segments.
    #[test]
    fn normalize_token_name_rejects_names_that_are_not_one_path_segment() {
        for name in [".", "..", "self", "a/b", "a?b", "a#b", "a%2fb", "토큰"] {
            let err = normalize_token_name(name).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidInput, "{name}");
        }
        assert_eq!(
            normalize_token_name("ci.prod_v2-x").unwrap(),
            "ci.prod_v2-x"
        );
    }

    /// Verify that `normalize_expires_at` is none without days and ahead of now with them.
    #[test]
    fn to_expires_at_is_none_without_days_and_ahead_of_now_with_them() {
        assert!(normalize_expires_at(None).unwrap().is_none());
        assert!(normalize_expires_at(Some(1)).unwrap().unwrap() > chrono::Utc::now());
        assert!(normalize_expires_at(Some(MAX_EXPIRES_IN_DAYS)).is_ok());
    }

    /// Verify that `normalize_expires_at` rejects non positive values.
    #[test]
    fn to_expires_at_rejects_non_positive_values() {
        let zero = normalize_expires_at(Some(0)).unwrap_err();
        let negative = normalize_expires_at(Some(-1)).unwrap_err();

        assert_eq!(zero.code(), ErrorCode::InvalidInput);
        assert_eq!(negative.code(), ErrorCode::InvalidInput);
    }

    /// Verify that `normalize_expires_at` rejects values beyond the cap.
    #[test]
    fn to_expires_at_rejects_values_beyond_the_cap() {
        let just_over = normalize_expires_at(Some(MAX_EXPIRES_IN_DAYS + 1)).unwrap_err();
        let overflow = normalize_expires_at(Some(i64::MAX)).unwrap_err();

        assert_eq!(just_over.code(), ErrorCode::InvalidInput);
        assert_eq!(overflow.code(), ErrorCode::InvalidInput);
    }
}
