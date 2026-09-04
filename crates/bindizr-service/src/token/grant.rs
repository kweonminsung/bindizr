//! Record-plane grants for API tokens, the HTTP twin of
//! [`crate::tsig_key::grant`]. A grant belongs to its token and names the
//! zone it covers.

use std::collections::HashMap;

use chrono::Utc;

use super::TokenService;
use crate::{
    authorization::Caller,
    error::ServiceError,
    grant_pattern::{normalize_pattern, normalize_types},
    model::token_grant::{TokenGrant, TokenGrantWithNames},
    repository::RepositoryService,
    zone::ZoneService,
};

/// Grants and revokes zone record rights for API tokens.
pub struct TokenGrantService;

impl TokenGrantService {
    /// Grant `token_name` record rights in `zone_name`, optionally restricted
    /// to a record name pattern and/or record types. Global tokens are
    /// rejected: they already cover every zone and never carry grants.
    pub async fn grant(
        caller: &Caller,
        token_name: &str,
        zone_name: &str,
        record_name_pattern: Option<&str>,
        record_types: Option<&str>,
    ) -> Result<TokenGrantWithNames, ServiceError> {
        caller.require_global("manage token grants")?;

        let token = TokenService::lookup_by_name(token_name).await?;
        if token.is_global {
            return Err(ServiceError::invalid_input(format!(
                "API token '{}' is global and already covers every zone; it cannot be granted one",
                token.name
            )));
        }
        let zone = ZoneService::lookup_by_name(zone_name).await?;

        let record_name_pattern = normalize_pattern(record_name_pattern)?;
        let record_types = normalize_types(record_types)?;

        let grant = RepositoryService::create_token_grant(TokenGrant {
            id: 0,
            zone_id: zone.id,
            api_token_id: token.id,
            record_name_pattern,
            record_types,
            created_at: Utc::now(),
        })
        .await?;

        Ok(TokenGrantWithNames {
            grant,
            api_token_name: token.name,
            zone_name: zone.name.to_string(),
        })
    }

    /// Every grant of `token_name`, with the zone each covers.
    pub async fn list_by_token(
        caller: &Caller,
        token_name: &str,
    ) -> Result<Vec<TokenGrantWithNames>, ServiceError> {
        caller.require_global("manage token grants")?;

        let token = TokenService::lookup_by_name(token_name).await?;
        let grants = RepositoryService::list_token_grants_by_token_id(token.id).await?;

        let zone_names: HashMap<i32, String> = RepositoryService::list_zones()
            .await?
            .into_iter()
            .map(|zone| (zone.id, zone.name.to_string()))
            .collect();

        Ok(grants
            .into_iter()
            .map(|grant| TokenGrantWithNames {
                zone_name: zone_names.get(&grant.zone_id).cloned().unwrap_or_default(),
                api_token_name: token.name.clone(),
                grant,
            })
            .collect())
    }

    /// Every grant that applies to `zone_name`, with the token each belongs to.
    pub async fn list_by_zone(
        caller: &Caller,
        zone_name: &str,
    ) -> Result<Vec<TokenGrantWithNames>, ServiceError> {
        caller.require_global("manage token grants")?;

        let zone = ZoneService::lookup_by_name(zone_name).await?;
        let grants = RepositoryService::list_token_grants_by_zone_id(zone.id).await?;

        let token_names: HashMap<i32, String> = RepositoryService::list_api_tokens()
            .await?
            .into_iter()
            .map(|token| (token.id, token.name))
            .collect();

        Ok(grants
            .into_iter()
            .map(|grant| TokenGrantWithNames {
                api_token_name: token_names
                    .get(&grant.api_token_id)
                    .cloned()
                    .unwrap_or_default(),
                zone_name: zone.name.to_string(),
                grant,
            })
            .collect())
    }

    /// Revoke one of `token_name`'s grants by id. An id that belongs to another
    /// token reads as not found.
    pub async fn revoke(
        caller: &Caller,
        token_name: &str,
        grant_id: i32,
    ) -> Result<(), ServiceError> {
        caller.require_global("manage token grants")?;

        let token = TokenService::lookup_by_name(token_name).await?;
        let grant = RepositoryService::get_token_grant(grant_id)
            .await?
            .filter(|grant| grant.api_token_id == token.id)
            .ok_or_else(|| ServiceError::token_grant_not_found(grant_id))?;

        RepositoryService::delete_token_grant(grant.id).await
    }
}
