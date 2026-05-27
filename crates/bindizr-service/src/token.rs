use chrono::{Duration, Utc};
use rand::{RngExt, distr::Alphanumeric};
use sha2::{Digest, Sha256};

use crate::model::api_token::ApiToken;

use super::{error::ServiceError, repository::RepositoryService};

pub struct TokenService;

pub(crate) fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

impl TokenService {
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

    pub async fn list_tokens() -> Result<Vec<ApiToken>, ServiceError> {
        let mut tokens = RepositoryService::get_all_api_tokens().await?;
        for token in &mut tokens {
            token.token.clear();
        }
        Ok(tokens)
    }

    pub async fn delete_token(token_id: i32) -> Result<(), ServiceError> {
        let exists = RepositoryService::get_api_token_by_id(token_id).await?;
        if exists.is_none() {
            return Err(ServiceError::NotFound("Token not found".to_string()));
        }

        RepositoryService::delete_api_token(token_id).await
    }
}

fn validate_expires_in_days(expires_in_days: Option<i64>) -> Result<(), ServiceError> {
    if let Some(days) = expires_in_days
        && days <= 0
    {
        return Err(ServiceError::BadRequest(
            "expires_in_days must be greater than 0".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_expires_in_days;
    use crate::error::ServiceError;

    #[test]
    fn validate_expires_in_days_accepts_none_and_positive_values() {
        validate_expires_in_days(None).unwrap();
        validate_expires_in_days(Some(1)).unwrap();
    }

    #[test]
    fn validate_expires_in_days_rejects_non_positive_values() {
        let zero = validate_expires_in_days(Some(0)).unwrap_err();
        let negative = validate_expires_in_days(Some(-1)).unwrap_err();

        assert!(matches!(zero, ServiceError::BadRequest(_)));
        assert!(matches!(negative, ServiceError::BadRequest(_)));
    }
}
