//! Authorize a caller through its role's grants. Invisible zones read as 404;
//! denied operations as 403.
//!
//! Management entry points authorize their [`Caller`]; the local socket passes
//! [`Caller::socket`]. DNS operations authorize through the ACL and the TSIG
//! key's role instead.

use std::sync::Arc;

use bindizr_core::{
    dns::name::OwnerName,
    model::{
        role::RoleId,
        role_grant::{Action, RoleGrant, RoleZoneScope},
        zone::ZoneId,
    },
};
use bindizr_db::LockLevel;
use chrono::{Duration, Utc};

use crate::{
    Context, Transaction,
    error::ServiceError,
    model::{
        api_token::ApiToken,
        record::RecordType,
        zone::Zone,
        zone_version::{ChangeActor, ChangeSource},
    },
    token::hash_token,
    zone::version::ChangeAttribution,
};

/// A request's access rights and change attribution, kept as independent facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    scope: CallerScope,
    attribution: ChangeAttribution,
}

/// Which resources the caller may access; transport and credential names do not decide it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CallerScope {
    Global,
    Role {
        id: RoleId,
        grants: Arc<[RoleGrant]>,
    },
}

/// One record write to authorize, its owner relative to the zone (stored form).
/// A `None` type matches only grants that constrain no type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordWrite<'a> {
    pub(crate) action: Action,
    pub(crate) relative_name: OwnerName,
    pub(crate) record_type: Option<&'a RecordType>,
}

impl Caller {
    /// Build the globally authorized caller after the daemon socket checks its peer UID.
    pub fn socket() -> Self {
        Self {
            scope: CallerScope::Global,
            attribution: ChangeAttribution {
                source: ChangeSource::Socket,
                actor: None,
            },
        }
    }

    /// Build the API caller when configuration explicitly disables token authentication.
    pub fn unauthenticated_api() -> Self {
        Self {
            scope: CallerScope::Global,
            attribution: ChangeAttribution {
                source: ChangeSource::Api,
                actor: None,
            },
        }
    }

    /// Build an API caller from an authenticated token and its role's loaded grants.
    pub(crate) fn from_token(token: &ApiToken, grants: Vec<RoleGrant>) -> Self {
        Self {
            scope: CallerScope::Role {
                id: token.role_id,
                grants: grants.into(),
            },
            attribution: ChangeAttribution {
                source: ChangeSource::Api,
                actor: Some(ChangeActor::Token {
                    name: token.name.clone(),
                }),
            },
        }
    }

    /// Return the request origin and credential snapshot recorded with a mutation.
    pub(crate) fn change_attribution(&self) -> &ChangeAttribution {
        &self.attribution
    }

    /// Validate a Bearer token and preload its role's grants. Record mutations
    /// reload and lock them inside their transaction.
    pub async fn authenticate(
        cx: &Context,
        bearer_token: &str,
    ) -> Result<(Caller, ApiToken), ServiceError> {
        let token = authenticate_token(cx, bearer_token).await?;
        let grants = bindizr_db::role_grant::list_by_role_id(cx.db(), token.role_id).await?;
        Ok((Caller::from_token(&token, grants), token))
    }

    /// Authorize an action on something no zone owns, which only an all-zones grant carries.
    pub(crate) fn authorize_action(&self, action: Action) -> Result<(), ServiceError> {
        let permitted = match &self.scope {
            CallerScope::Global => true,
            CallerScope::Role { grants, .. } => grants.iter().any(|grant| {
                grant.zone_scope == RoleZoneScope::All && grant.actions.contains(action)
            }),
        };
        if permitted {
            return Ok(());
        }
        Err(ServiceError::forbidden(format!(
            "role does not permit '{}' in every zone",
            action
        )))
    }

    /// Authorize an action on one zone: 404 when no grant reaches it, 403 without `action`.
    pub(crate) fn authorize_zone_action(
        &self,
        action: Action,
        zone: &Zone,
    ) -> Result<(), ServiceError> {
        let permitted = match &self.scope {
            CallerScope::Global => true,
            CallerScope::Role { grants, .. } => {
                grants.iter().any(|grant| grant.permits(action, zone.id))
            }
        };
        if permitted {
            return Ok(());
        }
        self.authorize_zone_visible(zone)?;
        Err(ServiceError::forbidden(format!(
            "role does not permit '{}' in zone '{}'",
            action, zone.name
        )))
    }

    /// The role whose grants bound the caller's visibility; `None` means
    /// unrestricted. List queries join it against the grants in SQL.
    pub(crate) fn scope_role_id(&self) -> Option<RoleId> {
        match &self.scope {
            CallerScope::Global => None,
            CallerScope::Role { id, .. } => Some(*id),
        }
    }

    /// The grants that bound the caller, or `None` when nothing does.
    pub(crate) fn grants(&self) -> Option<&[RoleGrant]> {
        match &self.scope {
            CallerScope::Global => None,
            CallerScope::Role { grants, .. } => Some(grants),
        }
    }

    /// Whether the caller may see `zone_id`: any grant reaching it, whatever its actions.
    pub(crate) fn sees_zone(&self, zone_id: ZoneId) -> bool {
        match &self.scope {
            CallerScope::Global => true,
            CallerScope::Role { grants, .. } => {
                grants.iter().any(|grant| grant.zone_scope.covers(zone_id))
            }
        }
    }

    /// 404 for zones the caller cannot see, so a role cannot probe zone
    /// existence.
    pub(crate) fn authorize_zone_visible(&self, zone: &Zone) -> Result<(), ServiceError> {
        if self.sees_zone(zone.id) {
            Ok(())
        } else {
            Err(ServiceError::zone_not_found(zone.name.as_str()))
        }
    }

    /// Authorize record writes, share-locking the role's grants so revocation
    /// waits for the mutation; zones no grant reaches read as `NotFound`.
    pub(crate) async fn authorize_record_writes_tx(
        &self,
        tx: &mut Transaction<'_>,
        zone: &Zone,
        writes: &[RecordWrite<'_>],
    ) -> Result<(), ServiceError> {
        match &self.scope {
            CallerScope::Global => Ok(()),
            CallerScope::Role { id, .. } => {
                let grants = bindizr_db::role_grant::list_by_role_id_covering_zone_tx(
                    tx,
                    *id,
                    zone.id,
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

    /// Whether a `record:read` grant covers a record of this name and type.
    pub(crate) fn sees_record(
        &self,
        zone_id: ZoneId,
        name: &OwnerName,
        record_type: Option<&RecordType>,
    ) -> bool {
        match &self.scope {
            CallerScope::Global => true,
            CallerScope::Role { grants, .. } => grants.iter().any(|grant| {
                grant.permits(Action::RecordRead, zone_id) && grant.matches(name, record_type)
            }),
        }
    }

    /// Authorize `action` over the zone whole. A view the zone is rebuilt from
    /// cannot be narrowed: half a zone re-applied deletes what it left out.
    pub(crate) fn authorize_zone_unrestricted(
        &self,
        action: Action,
        zone: &Zone,
    ) -> Result<(), ServiceError> {
        let unrestricted = match &self.scope {
            CallerScope::Global => true,
            CallerScope::Role { grants, .. } => grants
                .iter()
                .any(|grant| grant.permits(action, zone.id) && grant.is_unrestricted()),
        };
        if unrestricted {
            return Ok(());
        }

        self.authorize_zone_visible(zone)?;
        Err(ServiceError::forbidden(format!(
            "role does not permit '{}' over zone '{}' whole",
            action, zone.name
        )))
    }
}

/// Check whether the supplied grants cover every write's action, name and type.
fn authorize_with_grants(
    grants: &[RoleGrant],
    zone: &Zone,
    writes: &[RecordWrite<'_>],
) -> Result<(), ServiceError> {
    for write in writes {
        let granted = grants.iter().any(|grant| {
            grant.permits(write.action, zone.id)
                && grant.matches(&write.relative_name, write.record_type)
        });
        if !granted {
            return Err(ServiceError::forbidden(format!(
                "role does not permit '{}' on '{}' {} in zone '{}'",
                write.action,
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
                "invalid or expired token".to_string(),
            ));
        }
        Err(e) => {
            log::error!("Failed to validate token: {}", e);
            return Err(ServiceError::internal_with_source(
                "failed to validate token",
                e,
            ));
        }
    };

    if let Some(expires_at) = &stored_token.expires_at
        && Utc::now() >= *expires_at
    {
        return Err(ServiceError::invalid_token("token has expired"));
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
        ServiceError::internal_with_source("failed to update last_used_at", e)
    })?;

    Ok(updated_token)
}

#[cfg(test)]
mod tests;
