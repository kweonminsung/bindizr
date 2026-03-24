use chrono::{Duration, Utc};
use rand::{RngExt, distr::Alphanumeric};
use sha2::{Digest, Sha256};

use crate::database::model::api_token::ApiToken;

use super::{error::ServiceError, repository::RepositoryService};

pub struct TokenService;

impl TokenService {
    pub async fn create_token(
        description: Option<&str>,
        expires_in_days: Option<i64>,
    ) -> Result<ApiToken, ServiceError> {
        let random_string: String = rand::rng()
            .sample_iter(Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let mut hasher = Sha256::new();
        hasher.update(random_string);
        let token = hex::encode(hasher.finalize());

        let expires_at = expires_in_days.map(|days| Utc::now() + Duration::days(days));

        RepositoryService::create_api_token(ApiToken {
            id: 0,
            token,
            description: description.map(|d| d.to_string()),
            expires_at,
            created_at: Utc::now(),
            last_used_at: None,
        })
        .await
    }

    pub async fn list_tokens() -> Result<Vec<ApiToken>, ServiceError> {
        RepositoryService::get_all_api_tokens().await
    }

    pub async fn delete_token(token_id: i32) -> Result<(), ServiceError> {
        let exists = RepositoryService::get_api_token_by_id(token_id).await?;
        if exists.is_none() {
            return Err(ServiceError::NotFound("Token not found".to_string()));
        }

        RepositoryService::delete_api_token(token_id).await
    }
}
