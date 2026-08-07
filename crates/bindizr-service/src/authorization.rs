//! Caller identity and zone-scope authorization for the HTTP API. Scoped
//! tokens are the HTTP twin of non-global TSIG keys: record-plane only,
//! within `zone_token_policies` grants matched by the nsupdate pattern/type
//! rules. Invisible zones read as 404, denied writes as 403.

use std::{collections::HashSet, sync::Arc};

use crate::{
    RepositoryTx,
    error::ServiceError,
    model::{
        api_token::ApiToken, record::RecordType, zone::Zone, zone_token_policy::ZoneTokenPolicy,
    },
    repository::RepositoryService,
    zone::tsig_policy::{pattern_matches_name, types_match},
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

impl Caller {
    pub fn is_global(&self) -> bool {
        matches!(self, Caller::Global)
    }
}

/// Build the request's caller from its authenticated token, preloading a
/// scoped token's grants.
pub async fn caller_for_token(token: &ApiToken) -> Result<Caller, ServiceError> {
    if token.is_global {
        return Ok(Caller::Global);
    }
    let grants = RepositoryService::get_zone_token_policies_by_token_id(token.id).await?;
    Ok(Caller::Token {
        id: token.id,
        grants: grants.into(),
    })
}

/// One record-plane write to authorize: the owner name relative to the zone
/// (stored form) and its type. `None` types only match unrestricted policies.
pub struct RecordWrite<'a> {
    pub relative_name: &'a str,
    pub record_type: Option<&'a RecordType>,
}

/// Reject non-global callers for zone-plane and management operations.
pub fn require_global(caller: &Caller, action: &str) -> Result<(), ServiceError> {
    if caller.is_global() {
        return Ok(());
    }
    Err(ServiceError::forbidden(format!(
        "a global API token is required to {}",
        action
    )))
}

/// Zone ids the caller may see; `None` means unrestricted.
pub fn visible_zone_ids(caller: &Caller) -> Option<HashSet<i32>> {
    match caller {
        Caller::Global => None,
        Caller::Token { grants, .. } => Some(grants.iter().map(|p| p.zone_id).collect()),
    }
}

/// Whether the caller may see `zone_id`.
pub fn zone_visible(caller: &Caller, zone_id: i32) -> bool {
    match caller {
        Caller::Global => true,
        Caller::Token { grants, .. } => grants.iter().any(|p| p.zone_id == zone_id),
    }
}

/// 404 for zones the caller cannot see, so scoped tokens cannot probe zone
/// existence.
pub fn ensure_zone_visible(caller: &Caller, zone: &Zone) -> Result<(), ServiceError> {
    if zone_visible(caller, zone.id) {
        Ok(())
    } else {
        Err(ServiceError::zone_not_found(&zone.name))
    }
}

fn authorize_with_policies(
    policies: &[&ZoneTokenPolicy],
    zone: &Zone,
    writes: &[RecordWrite<'_>],
) -> Result<(), ServiceError> {
    for write in writes {
        let granted = policies.iter().any(|policy| {
            pattern_matches_name(&policy.record_name_pattern, write.relative_name)
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

/// Authorize record-plane writes in `zone`, re-reading the caller's policies
/// inside the transaction so the decision is atomic with the mutation.
pub async fn authorize_record_writes_tx(
    tx: &mut RepositoryTx<'_>,
    caller: &Caller,
    zone: &Zone,
    writes: &[RecordWrite<'_>],
) -> Result<(), ServiceError> {
    match caller {
        Caller::Global => Ok(()),
        Caller::Token { id, .. } => {
            let policies =
                RepositoryService::get_zone_token_policies_by_zone_and_token_tx(tx, zone.id, *id)
                    .await?;
            let policies: Vec<&ZoneTokenPolicy> = policies.iter().collect();
            authorize_with_policies(&policies, zone, writes)
        }
    }
}

#[cfg(test)]
mod tests;
