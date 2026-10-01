//! Authorize scoped tokens through record-plane grants using nsupdate pattern/type rules.
//! Invisible zones read as 404; denied writes as 403.
//!
//! Management entry points authorize their [`Caller`]; the local socket passes
//! [`Caller::Global`]. DNS operations authorize through ACL and TSIG instead.

use std::sync::Arc;

use bindizr_core::{
    dns::name::OwnerName,
    model::{api_token::TokenId, zone::ZoneId},
};
use bindizr_db::LockLevel;
use chrono::{Duration, Utc};

use crate::{
    Context, Transaction,
    error::ServiceError,
    model::{
        api_token::ApiToken, record::RecordType, token_grant::TokenGrant, zone::Zone,
        zone_version::ChangeSource,
    },
    token::hash_token,
    zone::version::ChangeSubject,
};

/// Request identity: `Global` for the local socket or disabled authentication;
/// otherwise a token with its audit name and scoped grants loaded by auth middleware.
#[derive(Debug, Clone)]
pub enum Caller {
    Global,
    GlobalToken {
        name: Arc<str>,
    },
    Token {
        id: TokenId,
        name: Arc<str>,
        grants: Arc<[TokenGrant]>,
    },
}

/// One record-plane write to authorize: the owner name relative to the zone
/// (stored form) and its type. `None` types only match unrestricted grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordWrite<'a> {
    pub(crate) relative_name: OwnerName,
    pub(crate) record_type: Option<&'a RecordType>,
}

impl Caller {
    /// Check whether the caller has unrestricted global access.
    fn is_global(&self) -> bool {
        matches!(self, Caller::Global | Caller::GlobalToken { .. })
    }

    /// The credential name a change made by this caller is recorded under.
    pub(crate) fn change_subject(&self) -> ChangeSubject {
        match self {
            Caller::Global => ChangeSubject {
                source: ChangeSource::Local,
                actor: None,
            },
            Caller::GlobalToken { name } | Caller::Token { name, .. } => ChangeSubject {
                source: ChangeSource::Token,
                actor: Some(name.to_string()),
            },
        }
    }

    /// Validate a Bearer token and preload grants for read checks. Mutations
    /// reload and lock the grants inside their transaction.
    pub async fn authenticate(
        cx: &Context,
        bearer_token: &str,
    ) -> Result<(Caller, ApiToken), ServiceError> {
        let token = authenticate_token(cx, bearer_token).await?;
        if token.is_global {
            let caller = Caller::GlobalToken {
                name: token.name.as_str().into(),
            };
            return Ok((caller, token));
        }
        let grants = bindizr_db::token_grant::list_by_token_id(cx.db(), token.id).await?;
        let caller = Caller::Token {
            id: token.id,
            name: token.name.as_str().into(),
            grants: grants.into(),
        };
        Ok((caller, token))
    }

    /// Reject non-global callers for zone-plane and management operations.
    pub(crate) fn authorize_global(&self, action: &str) -> Result<(), ServiceError> {
        if self.is_global() {
            return Ok(());
        }
        Err(ServiceError::forbidden(format!(
            "a global API token is required to {}",
            action
        )))
    }

    /// The token whose grants bound the caller's visibility; `None` means
    /// unrestricted. List queries join it against the grants in SQL.
    pub(crate) fn scope_token_id(&self) -> Option<TokenId> {
        match self {
            Caller::Global | Caller::GlobalToken { .. } => None,
            Caller::Token { id, .. } => Some(*id),
        }
    }

    /// The grants that bound the caller, or `None` when nothing does.
    pub(crate) fn grants(&self) -> Option<&[TokenGrant]> {
        match self {
            Caller::Global | Caller::GlobalToken { .. } => None,
            Caller::Token { grants, .. } => Some(grants),
        }
    }

    /// Whether the caller may see `zone_id`.
    pub(crate) fn sees_zone(&self, zone_id: ZoneId) -> bool {
        match self {
            Caller::Global | Caller::GlobalToken { .. } => true,
            Caller::Token { grants, .. } => grants.iter().any(|p| p.zone_id == zone_id),
        }
    }

    /// 404 for zones the caller cannot see, so scoped tokens cannot probe zone
    /// existence.
    pub(crate) fn authorize_zone_visible(&self, zone: &Zone) -> Result<(), ServiceError> {
        if self.sees_zone(zone.id) {
            Ok(())
        } else {
            Err(ServiceError::zone_not_found(zone.name.as_str()))
        }
    }

    /// Authorize record writes, share-locking grants so revocation waits for the mutation.
    /// Return `NotFound` for ungranted zones to prevent existence probes.
    pub(crate) async fn authorize_record_writes_tx(
        &self,
        tx: &mut Transaction<'_>,
        zone: &Zone,
        writes: &[RecordWrite<'_>],
    ) -> Result<(), ServiceError> {
        match self {
            Caller::Global | Caller::GlobalToken { .. } => Ok(()),
            Caller::Token { id, .. } => {
                let grants = bindizr_db::token_grant::list_by_zone_id_and_token_id_tx(
                    tx,
                    zone.id,
                    *id,
                    LockLevel::Shared,
                )
                .await?;
                // Ahead of the per-write loop, which a batch resolving to no
                // writes would otherwise pass vacuously.
                if grants.is_empty() {
                    return Err(ServiceError::zone_not_found(zone.name.as_str()));
                }
                authorize_with_grants(&grants, zone, writes)
            }
        }
    }

    /// Whether the caller may read a record of this name and type: a grant
    /// narrows reads the same way it narrows writes.
    pub(crate) fn sees_record(
        &self,
        zone_id: ZoneId,
        name: &OwnerName,
        record_type: Option<&RecordType>,
    ) -> bool {
        match self {
            Caller::Global | Caller::GlobalToken { .. } => true,
            Caller::Token { grants, .. } => grants
                .iter()
                .any(|grant| grant.zone_id == zone_id && grant.matches(name, record_type)),
        }
    }

    /// Whether the caller sees the zone whole. A view the zone is rebuilt
    /// from — its export, a stored version, a version diff — cannot be
    /// narrowed: half a zone re-applied deletes what it left out.
    pub(crate) fn authorize_zone_unrestricted(&self, zone: &Zone) -> Result<(), ServiceError> {
        let unrestricted = match self {
            Caller::Global | Caller::GlobalToken { .. } => true,
            Caller::Token { grants, .. } => grants
                .iter()
                .any(|grant| grant.zone_id == zone.id && grant.is_unrestricted()),
        };
        if unrestricted {
            return Ok(());
        }

        self.authorize_zone_visible(zone)?;
        Err(ServiceError::forbidden(format!(
            "API token is scoped to part of zone '{}', so it cannot read the zone whole",
            zone.name
        )))
    }
}

/// Check whether the supplied grants cover the requested zone operation.
fn authorize_with_grants(
    grants: &[TokenGrant],
    zone: &Zone,
    writes: &[RecordWrite<'_>],
) -> Result<(), ServiceError> {
    for write in writes {
        let granted = grants
            .iter()
            .any(|grant| grant.can_write && grant.matches(&write.relative_name, write.record_type));
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
async fn authenticate_token(cx: &Context, token_str: &str) -> Result<ApiToken, ServiceError> {
    let token_hash = hash_token(token_str);
    let stored_token = match bindizr_db::api_token::get_by_token(cx.db(), &token_hash).await {
        Ok(Some(token)) => token,
        Ok(None) => {
            return Err(ServiceError::invalid_token(
                "Invalid or expired token".to_string(),
            ));
        }
        Err(e) => {
            log::error!("Failed to validate token: {}", e);
            return Err(ServiceError::internal(
                "Failed to validate token".to_string(),
            ));
        }
    };

    if let Some(expires_at) = &stored_token.expires_at
        && Utc::now() >= *expires_at
    {
        return Err(ServiceError::invalid_token("Token has expired"));
    }

    let stamp_is_fresh = stored_token.last_used_at.is_some_and(|last_used| {
        Utc::now() - last_used < Duration::seconds(LAST_USED_STAMP_INTERVAL_SECS)
    });
    if stamp_is_fresh {
        return Ok(stored_token);
    }

    let updated_token = bindizr_db::api_token::update(
        cx.db(),
        ApiToken {
            last_used_at: Some(Utc::now()),
            ..stored_token
        },
    )
    .await
    .map_err(|e| {
        log::error!("Failed to update last_used_at: {}", e);
        ServiceError::internal("Failed to update last_used_at")
    })?;

    Ok(updated_token)
}

#[cfg(test)]
mod tests;
