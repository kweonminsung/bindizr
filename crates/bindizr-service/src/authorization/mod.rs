//! Caller identity and zone-scope authorization. Scoped tokens are the HTTP
//! twin of non-global TSIG keys: record-plane only, within their
//! `token_grants` rows matched by the nsupdate pattern/type rules.
//! Invisible zones read as 404, denied writes as 403.
//!
//! Every service operation a front end can reach takes a [`Caller`] and
//! decides its own authorization; a transport never gates on its own. The
//! daemon socket is reachable only by the local daemon owner, so it passes
//! [`Caller::Global`]. Operations serving the DNS protocol plane (transfers,
//! NOTIFY, nsupdate) take no caller — that plane authorizes by ACL and TSIG.

use std::sync::Arc;

use bindizr_core::dns::name::OwnerName;
use bindizr_db::repository::LockLevel;
use chrono::{Duration, Utc};

use crate::{
    RepositoryTx,
    error::ServiceError,
    grant_pattern::{MATCH_ANY, matches_name, matches_types},
    log_error,
    model::{
        api_token::ApiToken, record::RecordType, token_grant::TokenGrant, zone::Zone,
        zone_version::ChangeSource,
    },
    repository::RepositoryService,
    token::hash_token,
    zone::version::ChangeSubject,
};

/// The identity a request acts as. The daemon socket and disabled
/// authentication act as `Global`, behind no credential at all; a token
/// carries the name a change is recorded under, and a scoped one its grants,
/// preloaded once per request by the auth middleware.
#[derive(Debug, Clone)]
pub enum Caller {
    Global,
    GlobalToken {
        name: Arc<str>,
    },
    Token {
        id: i32,
        name: Arc<str>,
        grants: Arc<[TokenGrant]>,
    },
}

/// One record-plane write to authorize: the owner name relative to the zone
/// (stored form) and its type. `None` types only match unrestricted grants.
pub(crate) struct RecordWrite<'a> {
    pub(crate) relative_name: OwnerName,
    pub(crate) record_type: Option<&'a RecordType>,
}

impl Caller {
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

    /// Resolve who a Bearer token acts as: validate the token, then preload a
    /// scoped token's grants so the rest of the request decides against one
    /// read. The token row comes back too, since `Global` keeps no identity.
    pub async fn authenticate(bearer_token: &str) -> Result<(Caller, ApiToken), ServiceError> {
        let token = authenticate_token(bearer_token).await?;
        if token.is_global {
            let caller = Caller::GlobalToken {
                name: token.name.as_str().into(),
            };
            return Ok((caller, token));
        }
        let grants = RepositoryService::list_token_grants_by_token_id(token.id).await?;
        let caller = Caller::Token {
            id: token.id,
            name: token.name.as_str().into(),
            grants: grants.into(),
        };
        Ok((caller, token))
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

    /// The token whose grants bound the caller's visibility; `None` means
    /// unrestricted. List queries join it against the grants in SQL.
    pub(crate) fn scope_token_id(&self) -> Option<i32> {
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
    pub(crate) fn zone_visible(&self, zone_id: i32) -> bool {
        match self {
            Caller::Global | Caller::GlobalToken { .. } => true,
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
    /// grants inside the transaction so a concurrent revocation waits for
    /// this mutation instead of racing it. An ungranted zone reads as
    /// `NotFound`, so a write cannot probe zone existence either.
    pub(crate) async fn authorize_record_writes_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        writes: &[RecordWrite<'_>],
    ) -> Result<(), ServiceError> {
        match self {
            Caller::Global | Caller::GlobalToken { .. } => Ok(()),
            Caller::Token { id, .. } => {
                let grants = RepositoryService::list_token_grants_by_zone_id_and_token_id_tx(
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
    pub(crate) fn record_visible(
        &self,
        zone_id: i32,
        name: &OwnerName,
        record_type: Option<&RecordType>,
    ) -> bool {
        match self {
            Caller::Global | Caller::GlobalToken { .. } => true,
            Caller::Token { grants, .. } => grants.iter().any(|grant| {
                grant.zone_id == zone_id
                    && matches_name(&grant.record_name_pattern, name)
                    && matches_types(&grant.record_types, record_type)
            }),
        }
    }

    /// Whether the caller sees the zone whole. A view the zone is rebuilt
    /// from — its export, a stored version, a version diff — cannot be
    /// narrowed: half a zone re-applied deletes what it left out.
    pub(crate) fn ensure_zone_unrestricted(&self, zone: &Zone) -> Result<(), ServiceError> {
        let unrestricted = match self {
            Caller::Global | Caller::GlobalToken { .. } => true,
            Caller::Token { grants, .. } => grants.iter().any(|grant| {
                grant.zone_id == zone.id
                    && grant.record_name_pattern == MATCH_ANY
                    && grant.record_types == MATCH_ANY
            }),
        };
        if unrestricted {
            return Ok(());
        }

        self.ensure_zone_visible(zone)?;
        Err(ServiceError::forbidden(format!(
            "API token is scoped to part of zone '{}', so it cannot read the zone whole",
            zone.name
        )))
    }
}

fn authorize_with_grants(
    grants: &[TokenGrant],
    zone: &Zone,
    writes: &[RecordWrite<'_>],
) -> Result<(), ServiceError> {
    for write in writes {
        let granted = grants.iter().any(|grant| {
            grant.can_write
                && matches_name(&grant.record_name_pattern, &write.relative_name)
                && matches_types(&grant.record_types, write.record_type)
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
async fn authenticate_token(token_str: &str) -> Result<ApiToken, ServiceError> {
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
        return Err(ServiceError::invalid_token("Token has expired"));
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
        ServiceError::internal("Failed to update last_used_at")
    })?;

    Ok(updated_token)
}

#[cfg(test)]
mod tests;
