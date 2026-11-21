//! Creates, lists, and revokes API tokens.

use bindizr_core::model::api_token::{ApiToken, TokenId};
use bindizr_core::model::audit_log::{AuditEntity, AuditOperation};
use bindizr_core::model::role_grant::Action;
use chrono::{DateTime, Duration, Utc};
use rand::RngExt;
use rand::distr::Alphanumeric;
use ring::digest;
use ring::digest::SHA256;

use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::text::MAX_COLUMN_TEXT_LEN;
use crate::types::{
    CreateTokenRequest, MessageResponse, PaginatedResponse, TokenFilter, TokenResponse,
};
use crate::{Context, audit, pagination, role, text, transaction};

/// A century: inside every backend's timestamp range (MySQL DATETIME ends at 9999).
const MAX_EXPIRES_IN_DAYS: i64 = 36500;

/// Hash an API token for storage and lookup.
pub(crate) fn hash_token(token: &str) -> String {
    hex::encode(digest::digest(&SHA256, token.as_bytes()))
}

/// Create an API token in the request's role; the secret is shown this once.
pub async fn create(
    cx: &Context,
    caller: &Caller,
    request: &CreateTokenRequest,
) -> Result<(TokenResponse, String), ServiceError> {
    caller.authorize_action(Action::AccessManage)?;

    let name = normalize_name(&request.name)?;

    let role = role::lookup_by_name(cx, &request.role_name).await?;

    let description =
        text::normalize_description(request.description.as_deref(), ServiceError::invalid_input)?;
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

    let mut tx = transaction::begin_tx(cx, "failed to create token").await?;

    let apply_result: Result<_, ServiceError> = async {
        caller
            .reauthenticate_tx(&mut tx)
            .await?
            .authorize_action(Action::AccessManage)?;
        let token = bindizr_db::api_token::create_tx(
            &mut tx,
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
        .map_err(|error| {
            // A create that raced past the pre-check trips UNIQUE(name); the
            // backstop reads as the same conflict.
            if error.is_unique_violation() {
                ServiceError::token_conflict(&name)
            } else if error.is_foreign_key_violation() {
                ServiceError::role_not_found(&role.name)
            } else {
                error.into()
            }
        })?;
        audit::save_tx(
            &mut tx,
            AuditEntity::Token,
            &token.name,
            AuditOperation::Create,
            Some(format!(
                "role_name {}, expires_at {}",
                role.name,
                token
                    .expires_at
                    .map_or("never".to_string(), |at| at.format("%Y-%m-%d").to_string())
            )),
            caller.change_origin(),
        )
        .await?;

        Ok(token)
    }
    .await;

    let token = transaction::finish_tx(tx, apply_result, "failed to create token").await?;

    Ok((TokenResponse::from_token(&token, &role.name), raw_token))
}

/// List the API tokens, every one or one role's.
pub async fn list(
    cx: &Context,
    caller: &Caller,
    filter: &TokenFilter,
) -> Result<PaginatedResponse<TokenResponse>, ServiceError> {
    caller.authorize_action(Action::AccessManage)?;
    pagination::validate_page_limit(filter.limit)?;
    let role_id = match &filter.role_name {
        Some(name) => Some(role::lookup_by_name(cx, name).await?.id),
        None => None,
    };
    let filter = bindizr_db::api_token::ApiTokenFilter {
        role_id,
        limit: filter.limit,
        offset: filter.offset,
    };
    let total = bindizr_db::api_token::count_by_filter(cx.db(), &filter).await?;
    let rows = bindizr_db::api_token::list_by_filter_with_role(cx.db(), &filter).await?;
    Ok(pagination::build_paginated_response(
        rows.iter().map(TokenResponse::from).collect(),
        filter.limit,
        filter.offset,
        total,
    ))
}

/// Get `token` described with its role's name; any token may read itself.
pub async fn get_self(cx: &Context, token: &ApiToken) -> Result<TokenResponse, ServiceError> {
    let role = role::lookup(cx, token.role_id).await?;
    Ok(TokenResponse::from_token(token, &role.name))
}

/// Count the API tokens, read for the daemon's startup hint.
pub async fn count_all(cx: &Context) -> Result<u64, ServiceError> {
    Ok(bindizr_db::api_token::count_all(cx.db()).await?)
}

/// Delete the API token with the given name, returning `NotFound` if it
/// is absent.
pub async fn delete(
    cx: &Context,
    caller: &Caller,
    name: &str,
) -> Result<MessageResponse, ServiceError> {
    caller.authorize_action(Action::AccessManage)?;

    let token = lookup_by_name(cx, name).await?;

    let mut tx = transaction::begin_tx(cx, "failed to delete token").await?;

    let apply_result: Result<_, ServiceError> = async {
        caller
            .reauthenticate_tx(&mut tx)
            .await?
            .authorize_action(Action::AccessManage)?;

        // Removed meanwhile: not found, and no audit row for a deletion that was not one.
        if !bindizr_db::api_token::delete_tx(&mut tx, token.id).await? {
            return Err(ServiceError::token_not_found(&token.name));
        }

        audit::save_tx(
            &mut tx,
            AuditEntity::Token,
            &token.name,
            AuditOperation::Delete,
            None,
            caller.change_origin(),
        )
        .await
    }
    .await;

    transaction::finish_tx(tx, apply_result, "failed to delete token").await?;

    Ok(MessageResponse {
        message: format!("Token '{}' deleted successfully", token.name),
    })
}

/// Look up an API token by name or return a not-found error.
async fn lookup_by_name(cx: &Context, name: &str) -> Result<ApiToken, ServiceError> {
    bindizr_db::api_token::get_by_name(cx.db(), &normalize_name(name)?)
        .await?
        .ok_or_else(|| ServiceError::token_not_found(name))
}

/// Normalize a token name: lowercased so one name means one token on every
/// backend (MySQL compares case-insensitively), and kept to one URL path
/// segment for `/tokens/{name}`.
pub(crate) fn normalize_name(value: &str) -> Result<String, ServiceError> {
    let name = text::normalize_identifier(value, "token name", MAX_COLUMN_TEXT_LEN)?;

    // `self` is the lookup route.
    if name == "self" {
        return Err(ServiceError::invalid_input(format!(
            "token name must not be '{name}'"
        )));
    }

    Ok(name)
}

/// Normalize when a token created now expires; `None` never does.
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

    /// Verify that `normalize_name` trims and folds case.
    #[test]
    fn normalize_name_trims_and_folds_case() {
        assert_eq!(normalize_name(" external-dns ").unwrap(), "external-dns");
        assert_eq!(normalize_name("Deploy").unwrap(), "deploy");
        assert_eq!(
            normalize_name("DEPLOY").unwrap(),
            normalize_name("deploy").unwrap()
        );
    }

    /// Verify that `normalize_name` rejects empty and whitespace names.
    #[test]
    fn normalize_name_rejects_empty_and_whitespace_names() {
        for name in ["", "   ", "bad name", "bad\tname"] {
            let error = normalize_name(name).unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidInput);
        }
    }

    /// Verify that token names that cannot remain one URL path segment are rejected.
    ///
    /// `/` splits segments, `?` and `#` terminate them, and URL normalization removes dot segments.
    #[test]
    fn normalize_name_rejects_names_that_are_not_one_path_segment() {
        for name in [".", "..", "self", "a/b", "a?b", "a#b", "a%2fb", "토큰"] {
            let error = normalize_name(name).unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidInput, "{name}");
        }

        assert_eq!(normalize_name("ci.prod_v2-x").unwrap(), "ci.prod_v2-x");
    }

    /// Verify that `normalize_expires_at` is none without days and ahead of now with them.
    #[test]
    fn normalize_expires_at_returns_optional_future_deadline() {
        assert!(normalize_expires_at(None).unwrap().is_none());
        assert!(normalize_expires_at(Some(1)).unwrap().unwrap() > Utc::now());
        assert!(normalize_expires_at(Some(MAX_EXPIRES_IN_DAYS)).is_ok());
    }

    /// Verify that `normalize_expires_at` rejects non positive values.
    #[test]
    fn normalize_expires_at_rejects_non_positive_values() {
        let zero = normalize_expires_at(Some(0)).unwrap_err();
        let negative = normalize_expires_at(Some(-1)).unwrap_err();

        assert_eq!(zero.code(), ErrorCode::InvalidInput);
        assert_eq!(negative.code(), ErrorCode::InvalidInput);
    }

    /// Verify that `normalize_expires_at` rejects values beyond the cap.
    #[test]
    fn normalize_expires_at_rejects_values_beyond_cap() {
        let just_over = normalize_expires_at(Some(MAX_EXPIRES_IN_DAYS + 1)).unwrap_err();
        let overflow = normalize_expires_at(Some(i64::MAX)).unwrap_err();

        assert_eq!(just_over.code(), ErrorCode::InvalidInput);
        assert_eq!(overflow.code(), ErrorCode::InvalidInput);
    }
}
