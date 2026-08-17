//! Caller identity and zone-scope authorization. Scoped tokens are the HTTP
//! twin of non-global TSIG keys: record-plane only, within
//! `zone_token_policies` grants matched by the nsupdate pattern/type rules.
//! Invisible zones read as 404, denied writes as 403.
//!
//! Every service operation a front end can reach takes a [`Caller`] and
//! decides its own authorization; a transport never gates on its own. The
//! daemon socket is reachable only by the local daemon owner, so it passes
//! [`Caller::Global`]. Operations serving the DNS protocol plane (transfers,
//! NOTIFY, nsupdate) take no caller — that plane authorizes by ACL and TSIG.

use std::{collections::HashSet, sync::Arc};

use bindizr_core::dns::name::OwnerName;
use bindizr_db::repository::LockLevel;
use chrono::{Duration, Utc};

use crate::{
    RepositoryTx,
    error::ServiceError,
    log_error,
    model::{
        api_token::ApiToken, record::RecordType, zone::Zone, zone_token_policy::ZoneTokenPolicy,
    },
    policy_pattern::{pattern_matches_name, types_match},
    repository::RepositoryService,
    token::hash_token,
};

/// The identity a request acts as. The daemon socket and disabled
/// authentication act as `Global`; scoped tokens carry their grants,
/// preloaded once per request by the auth middleware.
#[derive(Debug, Clone)]
pub enum Caller {
    Global,
    Token {
        id: i32,
        grants: Arc<[ZoneTokenPolicy]>,
    },
}

/// One record-plane write to authorize: the owner name relative to the zone
/// (stored form) and its type. `None` types only match unrestricted policies.
pub(crate) struct RecordWrite<'a> {
    pub(crate) relative_name: OwnerName,
    pub(crate) record_type: Option<&'a RecordType>,
}

impl Caller {
    fn is_global(&self) -> bool {
        matches!(self, Caller::Global)
    }

    /// Resolve who a Bearer token acts as: validate the token, then preload a
    /// scoped token's grants so the rest of the request decides against one
    /// read.
    pub async fn authenticate(bearer_token: &str) -> Result<Caller, ServiceError> {
        let token = validate_token(bearer_token).await?;
        if token.is_global {
            return Ok(Caller::Global);
        }
        let grants = RepositoryService::list_zone_token_policies_by_token_id(token.id).await?;
        Ok(Caller::Token {
            id: token.id,
            grants: grants.into(),
        })
    }

    /// Reject non-global callers for zone-plane and management operations.
    pub(crate) fn require_global(&self, action: &str) -> Result<(), ServiceError> {
        if self.is_global() {
            return Ok(());
        }
        Err(ServiceError::forbidden(format!(
            "a global API token is required to {}",
            action
        )))
    }

    /// Zone ids the caller may see; `None` means unrestricted.
    pub(crate) fn visible_zone_ids(&self) -> Option<HashSet<i32>> {
        match self {
            Caller::Global => None,
            Caller::Token { grants, .. } => Some(grants.iter().map(|p| p.zone_id).collect()),
        }
    }

    /// Whether the caller may see `zone_id`.
    pub(crate) fn zone_visible(&self, zone_id: i32) -> bool {
        match self {
            Caller::Global => true,
            Caller::Token { grants, .. } => grants.iter().any(|p| p.zone_id == zone_id),
        }
    }

    /// 404 for zones the caller cannot see, so scoped tokens cannot probe zone
    /// existence.
    pub(crate) fn ensure_zone_visible(&self, zone: &Zone) -> Result<(), ServiceError> {
        if self.zone_visible(zone.id) {
            Ok(())
        } else {
            Err(ServiceError::zone_not_found(zone.name.as_str()))
        }
    }

    /// Authorize record-plane writes in `zone`, share-locking the caller's
    /// policies inside the transaction so a concurrent revocation waits for
    /// this mutation instead of racing it.
    pub(crate) async fn authorize_record_writes_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        writes: &[RecordWrite<'_>],
    ) -> Result<(), ServiceError> {
        match self {
            Caller::Global => Ok(()),
            Caller::Token { id, .. } => {
                let policies = RepositoryService::list_zone_token_policies_by_zone_and_token_tx(
                    tx,
                    zone.id,
                    *id,
                    LockLevel::Shared,
                )
                .await?;
                // Ahead of the per-write loop, which a batch resolving to no
                // writes would otherwise pass vacuously.
                if policies.is_empty() {
                    return Err(ServiceError::forbidden(format!(
                        "API token is not allowed to manage records in zone '{}'",
                        zone.name
                    )));
                }
                authorize_with_policies(&policies, zone, writes)
            }
        }
    }
}

fn authorize_with_policies(
    policies: &[ZoneTokenPolicy],
    zone: &Zone,
    writes: &[RecordWrite<'_>],
) -> Result<(), ServiceError> {
    for write in writes {
        let granted = policies.iter().any(|policy| {
            pattern_matches_name(&policy.record_name_pattern, &write.relative_name)
                && types_match(&policy.record_types, write.record_type)
        });
        if !granted {
            return Err(ServiceError::forbidden(format!(
                "API token is not allowed to manage '{}' {} in zone '{}'",
                write.relative_name,
                write
                    .record_type
                    .map(RecordType::as_str)
                    .unwrap_or("records"),
                zone.name
            )));
        }
    }
    Ok(())
}

/// How long a `last_used_at` stamp stays fresh; stamping every request would
/// put a database write on the hot path for no added precision.
const LAST_USED_STAMP_INTERVAL_SECS: i64 = 60;

/// Validate an API token, rejecting expired tokens and stamping `last_used_at`.
async fn validate_token(token_str: &str) -> Result<ApiToken, ServiceError> {
    let token_hash = hash_token(token_str);
    let stored_token = match RepositoryService::get_api_token_by_token(&token_hash).await {
        Ok(Some(token)) => token,
        Ok(None) => {
            return Err(ServiceError::invalid_token(
                "Invalid or expired token".to_string(),
            ));
        }
        Err(e) => {
            log_error!("Failed to validate token: {}", e);
            return Err(ServiceError::internal(
                "Failed to validate token".to_string(),
            ));
        }
    };

    if let Some(expires_at) = &stored_token.expires_at
        && Utc::now() >= *expires_at
    {
        return Err(ServiceError::invalid_token("Token has expired".to_string()));
    }

    let stamp_is_fresh = stored_token.last_used_at.is_some_and(|last_used| {
        Utc::now() - last_used < Duration::seconds(LAST_USED_STAMP_INTERVAL_SECS)
    });
    if stamp_is_fresh {
        return Ok(stored_token);
    }

    let updated_token = RepositoryService::update_api_token(ApiToken {
        last_used_at: Some(Utc::now()),
        ..stored_token
    })
    .await
    .map_err(|e| {
        log_error!("Failed to update last_used_at: {}", e);
        ServiceError::internal("Failed to update last_used_at".to_string())
    })?;

    Ok(updated_token)
}

#[cfg(test)]
mod tests;
