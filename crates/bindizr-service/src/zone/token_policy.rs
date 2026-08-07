//! Per-zone record-plane grants for API tokens, the HTTP twin of
//! [`super::tsig_policy`].

use chrono::Utc;

use crate::{
    error::ServiceError,
    model::{api_token::ApiToken, zone_token_policy::ZoneTokenPolicy},
    repository::RepositoryService,
    zone::{
        tsig_policy::{normalize_pattern, normalize_types},
        validation::normalize_zone_name,
    },
};

/// A zone token policy joined with the name of the token it grants.
#[derive(Debug, Clone)]
pub struct ZoneTokenPolicyWithToken {
    pub policy: ZoneTokenPolicy,
    pub api_token_name: String,
}

/// Grants and revokes per-zone record rights for API tokens.
pub struct ZoneTokenPolicyService;

impl ZoneTokenPolicyService {
    /// Grant token `token_name` record rights in `zone_name`, optionally
    /// restricted to a record name pattern and/or record types. Global tokens
    /// are rejected: they already cover every zone and never carry policies.
    pub async fn add(
        zone_name: &str,
        token_name: &str,
        record_name_pattern: Option<&str>,
        record_types: Option<&str>,
    ) -> Result<ZoneTokenPolicyWithToken, ServiceError> {
        let zone = find_zone(zone_name).await?;
        let token = find_token(token_name).await?;

        if token.is_global {
            return Err(ServiceError::invalid_input(format!(
                "API token '{}' is global and already covers every zone; policies cannot be added to it",
                token.name
            )));
        }

        let record_name_pattern = normalize_pattern(record_name_pattern)?;
        let record_types = normalize_types(record_types)?;

        let policy = RepositoryService::create_zone_token_policy(ZoneTokenPolicy {
            id: 0,
            zone_id: zone.id,
            api_token_id: token.id,
            record_name_pattern,
            record_types,
            created_at: Utc::now(),
        })
        .await?;

        Ok(ZoneTokenPolicyWithToken {
            policy,
            api_token_name: token.name,
        })
    }

    /// List all token policies of a zone with their token names.
    pub async fn list(zone_name: &str) -> Result<Vec<ZoneTokenPolicyWithToken>, ServiceError> {
        let zone = find_zone(zone_name).await?;
        let policies = RepositoryService::get_zone_token_policies_by_zone_id(zone.id).await?;

        let tokens = RepositoryService::get_all_api_tokens().await?;
        let token_name = |id: i32| {
            tokens
                .iter()
                .find(|token| token.id == id)
                .map(|token| token.name.clone())
                .unwrap_or_default()
        };

        Ok(policies
            .into_iter()
            .map(|policy| ZoneTokenPolicyWithToken {
                api_token_name: token_name(policy.api_token_id),
                policy,
            })
            .collect())
    }

    /// Remove one policy of a zone by policy id.
    pub async fn remove(zone_name: &str, policy_id: i32) -> Result<(), ServiceError> {
        let zone = find_zone(zone_name).await?;

        let policy = RepositoryService::get_zone_token_policy_by_id(policy_id)
            .await?
            .filter(|policy| policy.zone_id == zone.id)
            .ok_or_else(|| ServiceError::token_policy_not_found(policy_id))?;

        RepositoryService::delete_zone_token_policy(policy.id).await
    }
}

async fn find_zone(zone_name: &str) -> Result<crate::model::zone::Zone, ServiceError> {
    let name = normalize_zone_name(zone_name)?;
    RepositoryService::get_zone_by_name(&name)
        .await?
        .ok_or_else(|| ServiceError::zone_not_found(zone_name))
}

async fn find_token(token_name: &str) -> Result<ApiToken, ServiceError> {
    RepositoryService::get_api_token_by_name(token_name.trim())
        .await?
        .ok_or_else(|| ServiceError::token_not_found(token_name))
}
