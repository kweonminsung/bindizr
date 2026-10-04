//! Authorize a caller through its role's grants. Invisible zones read as 404;
//! denied operations as 403.
//!
//! Management entry points authorize their [`Caller`]; the local socket passes
//! [`Caller::socket`]. DNS operations authorize through the ACL and the TSIG
//! key's role instead.

use bindizr_core::{
    dns::name::OwnerName,
    model::{
        api_token::TokenId,
        role::RoleId,
        role_grant::{Action, RoleGrant, RoleGrants},
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
        record::{Record, RecordData, RecordType},
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
    /// A role's caller, through the token that authenticated it.
    Role {
        id: RoleId,
        token_id: TokenId,
        grants: RoleGrants,
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

/// A record as grants see it: an owner name and a type.
pub(crate) trait GrantedRecord {
    /// The owner name, relative to its zone (stored form).
    fn name(&self) -> &OwnerName;

    /// The record's type.
    fn record_type(&self) -> &RecordType;
}

impl GrantedRecord for Record {
    /// The stored owner name.
    fn name(&self) -> &OwnerName {
        &self.name
    }

    /// The stored type.
    fn record_type(&self) -> &RecordType {
        &self.record_type
    }
}

impl GrantedRecord for RecordData {
    /// The owner name.
    fn name(&self) -> &OwnerName {
        &self.name
    }

    /// The type.
    fn record_type(&self) -> &RecordType {
        &self.record_type
    }
}

/// Rows of one zone the caller may read. A response renders existing rows
/// only from this type, built by [`Caller::readable_records`] or a
/// [`WholeZoneRead`], so a flow cannot show a row it never checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReadableRecords<T>(Vec<T>);

impl<T> ReadableRecords<T> {
    /// Add a row the caller is writing: what it sends is its own to see.
    pub(crate) fn push_written(&mut self, row: T) {
        self.0.push(row);
    }

    /// The rows.
    pub(crate) fn as_slice(&self) -> &[T] {
        &self.0
    }
}

/// Proof that the caller may read a zone's records whole, from
/// [`Caller::authorize_whole_zone_read`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WholeZoneRead {
    _proof: (),
}

impl WholeZoneRead {
    /// Every row of the zone, unfiltered: the proof covers them all.
    pub(crate) fn readable_records<T>(self, rows: Vec<T>) -> ReadableRecords<T> {
        ReadableRecords(rows)
    }
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
                token_id: token.id,
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
        if self
            .grants()
            .is_none_or(|grants| grants.permits_all_zones(action))
        {
            return Ok(());
        }
        Err(ServiceError::forbidden(format!(
            "role does not permit '{}' in all zones",
            action
        )))
    }

    /// Authorize an action on one zone: 404 when no grant reaches it, 403 without `action`.
    pub(crate) fn authorize_zone_action(
        &self,
        action: Action,
        zone: &Zone,
    ) -> Result<(), ServiceError> {
        if self
            .grants()
            .is_none_or(|grants| grants.permits(action, zone.id))
        {
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
    pub(crate) fn grants(&self) -> Option<&RoleGrants> {
        match &self.scope {
            CallerScope::Global => None,
            CallerScope::Role { grants, .. } => Some(grants),
        }
    }

    /// Whether the caller may see `zone_id`: any grant reaching it, whatever its actions.
    pub(crate) fn sees_zone(&self, zone_id: ZoneId) -> bool {
        self.grants()
            .is_none_or(|grants| grants.reaches_zone(zone_id))
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

    /// This caller authenticated again in `tx`: its token and its role's grants
    /// re-read share-locked, so deleting the token or revoking a grant waits for
    /// the transaction; a write takes it right after its zone row.
    pub(crate) async fn reauthenticate_tx(
        &self,
        tx: &mut Transaction<'_>,
    ) -> Result<Caller, ServiceError> {
        match &self.scope {
            CallerScope::Global => Ok(self.clone()),
            CallerScope::Role { token_id, .. } => {
                let token = bindizr_db::api_token::get_tx(tx, *token_id, LockLevel::Shared)
                    .await?
                    .filter(|token| {
                        token
                            .expires_at
                            .is_none_or(|expires_at| Utc::now() < expires_at)
                    })
                    .ok_or_else(|| ServiceError::invalid_token("invalid or expired token"))?;
                let grants = bindizr_db::role_grant::list_by_role_id_tx(
                    tx,
                    token.role_id,
                    LockLevel::Shared,
                )
                .await?;
                Ok(Caller {
                    scope: CallerScope::Role {
                        id: token.role_id,
                        token_id: token.id,
                        grants: grants.into(),
                    },
                    attribution: self.attribution.clone(),
                })
            }
        }
    }

    /// Authorize record writes in `zone`; a zone no grant reaches reads as
    /// `NotFound`.
    pub(crate) fn authorize_record_writes(
        &self,
        zone: &Zone,
        writes: &[RecordWrite<'_>],
    ) -> Result<(), ServiceError> {
        let Some(grants) = self.grants() else {
            return Ok(());
        };
        // Ahead of the per-write loop, which a batch resolving to no writes
        // would otherwise pass vacuously.
        if !grants.reaches_zone(zone.id) {
            return Err(ServiceError::zone_not_found(zone.name.as_str()));
        }
        authorize_with_grants(grants, zone, writes)
    }

    /// Whether `record:read` or the write `action` covers a record of this
    /// name and type, so a write-only grant finds what it may change.
    pub(crate) fn reaches_record(
        &self,
        action: Action,
        zone_id: ZoneId,
        name: &OwnerName,
        record_type: Option<&RecordType>,
    ) -> bool {
        self.grants()
            .is_none_or(|grants| grants.reaches_record(action, zone_id, name, record_type))
    }

    /// Whether a `record:read` grant covers a record of this name and type.
    pub(crate) fn sees_record(
        &self,
        zone_id: ZoneId,
        name: &OwnerName,
        record_type: Option<&RecordType>,
    ) -> bool {
        self.grants().is_none_or(|grants| {
            grants.covers_record(Action::RecordRead, zone_id, name, record_type)
        })
    }

    /// The rows a `record:read` grant covers; the rest are dropped, so a
    /// write-only grant learns what it writes and nothing already there.
    pub(crate) fn readable_records<T: GrantedRecord>(
        &self,
        zone_id: ZoneId,
        rows: impl IntoIterator<Item = T>,
    ) -> ReadableRecords<T> {
        ReadableRecords(
            rows.into_iter()
                .filter(|row| self.sees_record(zone_id, row.name(), Some(row.record_type())))
                .collect(),
        )
    }

    /// The record actions the caller may take on one record, so a client
    /// offers exactly the ones the service would allow.
    pub(crate) fn record_actions(
        &self,
        zone_id: ZoneId,
        name: &OwnerName,
        record_type: &RecordType,
    ) -> Vec<Action> {
        [
            Action::RecordRead,
            Action::RecordUpdate,
            Action::RecordDelete,
        ]
        .into_iter()
        .filter(|&action| {
            self.grants()
                .is_none_or(|grants| grants.covers_record(action, zone_id, name, Some(record_type)))
        })
        .collect()
    }

    /// Authorize reading the zone's records whole, handing back the proof
    /// that renders them unfiltered.
    pub(crate) fn authorize_whole_zone_read(
        &self,
        zone: &Zone,
    ) -> Result<WholeZoneRead, ServiceError> {
        self.authorize_whole_zone(Action::RecordRead, zone)?;
        Ok(WholeZoneRead { _proof: () })
    }

    /// Authorize `action` over all zones whole: what a zone created later
    /// needs, since only an all-zones grant reaches it.
    pub(crate) fn authorize_all_whole_zones(&self, action: Action) -> Result<(), ServiceError> {
        if self
            .grants()
            .is_none_or(|grants| grants.covers_all_whole_zones(action))
        {
            return Ok(());
        }
        Err(ServiceError::forbidden(format!(
            "role does not permit '{}' over all zones whole",
            action
        )))
    }

    /// Authorize `action` over the zone whole. A view the zone is rebuilt from
    /// cannot be narrowed: half a zone re-applied deletes what it left out.
    pub(crate) fn authorize_whole_zone(
        &self,
        action: Action,
        zone: &Zone,
    ) -> Result<(), ServiceError> {
        if self
            .grants()
            .is_none_or(|grants| grants.covers_whole_zone(action, zone.id))
        {
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
    grants: &RoleGrants,
    zone: &Zone,
    writes: &[RecordWrite<'_>],
) -> Result<(), ServiceError> {
    for write in writes {
        if !grants.covers_record(
            write.action,
            zone.id,
            &write.relative_name,
            write.record_type,
        ) {
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
