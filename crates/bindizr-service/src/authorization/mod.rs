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

use crate::{
    RepositoryTx,
    error::ServiceError,
    model::{
        api_token::ApiToken, record::RecordType, zone::Zone, zone_token_policy::ZoneTokenPolicy,
    },
    policy_pattern::{pattern_matches_name, types_match},
    repository::RepositoryService,
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
pub struct RecordWrite<'a> {
    pub relative_name: OwnerName,
    pub record_type: Option<&'a RecordType>,
}

impl Caller {
    pub fn is_global(&self) -> bool {
        matches!(self, Caller::Global)
    }

    /// Build the request's caller from its authenticated token, preloading a
    /// scoped token's grants.
    pub async fn for_token(token: &ApiToken) -> Result<Caller, ServiceError> {
        if token.is_global {
            return Ok(Caller::Global);
        }
        let grants = RepositoryService::get_zone_token_policies_by_token_id(token.id).await?;
        Ok(Caller::Token {
            id: token.id,
            grants: grants.into(),
        })
    }

    /// Reject non-global callers for zone-plane and management operations.
    pub fn require_global(&self, action: &str) -> Result<(), ServiceError> {
        if self.is_global() {
            return Ok(());
        }
        Err(ServiceError::forbidden(format!(
            "a global API token is required to {}",
            action
        )))
    }

    /// Zone ids the caller may see; `None` means unrestricted.
    pub fn visible_zone_ids(&self) -> Option<HashSet<i32>> {
        match self {
            Caller::Global => None,
            Caller::Token { grants, .. } => Some(grants.iter().map(|p| p.zone_id).collect()),
        }
    }

    /// Whether the caller may see `zone_id`.
    pub fn zone_visible(&self, zone_id: i32) -> bool {
        match self {
            Caller::Global => true,
            Caller::Token { grants, .. } => grants.iter().any(|p| p.zone_id == zone_id),
        }
    }

    /// 404 for zones the caller cannot see, so scoped tokens cannot probe zone
    /// existence.
    pub fn ensure_zone_visible(&self, zone: &Zone) -> Result<(), ServiceError> {
        if self.zone_visible(zone.id) {
            Ok(())
        } else {
            Err(ServiceError::zone_not_found(&zone.name))
        }
    }

    /// Authorize record-plane writes in `zone`, re-reading the caller's
    /// policies inside the transaction so the decision is atomic with the
    /// mutation.
    pub(crate) async fn authorize_record_writes_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        writes: &[RecordWrite<'_>],
    ) -> Result<(), ServiceError> {
        match self {
            Caller::Global => Ok(()),
            Caller::Token { id, .. } => {
                let policies = RepositoryService::get_zone_token_policies_by_zone_and_token_tx(
                    tx, zone.id, *id,
                )
                .await?;
                let policies: Vec<&ZoneTokenPolicy> = policies.iter().collect();
                authorize_with_policies(&policies, zone, writes)
            }
        }
    }
}

fn authorize_with_policies(
    policies: &[&ZoneTokenPolicy],
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

#[cfg(test)]
mod tests;
