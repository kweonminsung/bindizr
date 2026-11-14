//! Authorize [`Caller`] through role grants: invisible zones yield 404, denied actions 403.
//! Socket callers are unrestricted; DNS callers use TSIG or explicitly admitted unsigned access.

use bindizr_core::dns::name::OwnerName;
use bindizr_core::model::api_token::{ApiToken, TokenId};
use bindizr_core::model::change::{ChangeActor, ChangeSource};
use bindizr_core::model::record::{Record, RecordData, RecordType};
use bindizr_core::model::role::RoleId;
use bindizr_core::model::role_grant::{Action, RoleGrant, RoleGrants};
use bindizr_core::model::tsig_key::{TsigKey, TsigKeyId};
use bindizr_core::model::zone::{Zone, ZoneId};
use bindizr_db::LockLevel;
use chrono::{Duration, Utc};

use crate::change::ChangeOrigin;
use crate::error::ServiceError;
use crate::{Context, Transaction, token};

/// How long a `last_used_at` stamp stays fresh; stamping every request would
/// put a database write on the hot path for no added precision.
const LAST_USED_STAMP_INTERVAL_SECS: i64 = 60;

/// A request's access rights and change origin, kept as independent facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    scope: CallerScope,
    origin: ChangeOrigin,
}

impl Caller {
    /// Build the globally authorized caller after the daemon socket checks its peer UID.
    pub fn socket() -> Self {
        Self {
            scope: CallerScope::Global,
            origin: ChangeOrigin {
                source: ChangeSource::Socket,
                actor: None,
            },
        }
    }

    /// Build the API caller when configuration explicitly disables token authentication.
    pub fn unauthenticated_api() -> Self {
        Self {
            scope: CallerScope::Global,
            origin: ChangeOrigin {
                source: ChangeSource::Api,
                actor: None,
            },
        }
    }

    /// Build a global caller for unsigned DNS requests admitted by the address ACL
    /// or `dns.nsupdate.tsig_required = false`.
    pub fn unsigned_dns() -> Self {
        Self {
            scope: CallerScope::Global,
            origin: ChangeOrigin {
                source: ChangeSource::Nsupdate,
                actor: None,
            },
        }
    }

    /// Return whether this is the unsigned DNS caller: a request no TSIG key named,
    /// which the policy on unsigned requests may still refuse.
    pub fn is_unsigned_dns(&self) -> bool {
        self.origin.source == ChangeSource::Nsupdate && self.origin.actor.is_none()
    }

    /// Build an API caller from an authenticated token and its role's loaded grants.
    pub(crate) fn from_token(token: &ApiToken, grants: Vec<RoleGrant>) -> Self {
        Self {
            scope: CallerScope::Role {
                id: token.role_id,
                credential: Credential::Token(token.id),
                grants: grants.into(),
            },
            origin: ChangeOrigin {
                source: ChangeSource::Api,
                actor: Some(ChangeActor::Token {
                    name: token.name.clone(),
                }),
            },
        }
    }

    /// Return the request origin and credential snapshot recorded with a mutation.
    pub(crate) fn change_origin(&self) -> &ChangeOrigin {
        &self.origin
    }

    /// Build the DNS plane's caller from a verified key and its role's loaded
    /// grants; its change origin preserves the nsupdate path and key name.
    pub(crate) fn from_tsig_key(tsig_key: &TsigKey, grants: Vec<RoleGrant>) -> Self {
        Self {
            scope: CallerScope::Role {
                id: tsig_key.role_id,
                credential: Credential::TsigKey(tsig_key.id),
                grants: grants.into(),
            },
            origin: ChangeOrigin {
                source: ChangeSource::Nsupdate,
                actor: Some(ChangeActor::TsigKey {
                    name: tsig_key.name.clone(),
                }),
            },
        }
    }

    /// Validate a Bearer token, stamping `last_used_at`, and preload its
    /// role's grants; a mutation reloads and locks them in its transaction.
    pub async fn authenticate_token(
        cx: &Context,
        bearer_token: &str,
    ) -> Result<(Self, ApiToken), ServiceError> {
        let token_hash = token::hash_token(bearer_token);

        let stored_token = match bindizr_db::api_token::get_by_token(cx.db(), &token_hash).await {
            Ok(Some(token)) => token,
            Ok(None) => return Err(ServiceError::invalid_token("invalid or expired token")),
            Err(error) => {
                log::error!("Failed to validate token: {error}");
                return Err(ServiceError::internal_with_source(
                    "failed to validate token",
                    error,
                ));
            }
        };

        if let Some(expires_at) = stored_token.expires_at
            && Utc::now() >= expires_at
        {
            return Err(ServiceError::invalid_token("token has expired"));
        }

        let stamp_is_fresh = stored_token.last_used_at.is_some_and(|last_used| {
            Utc::now() - last_used < Duration::seconds(LAST_USED_STAMP_INTERVAL_SECS)
        });

        let token = if stamp_is_fresh {
            stored_token
        } else {
            let last_used_at = Utc::now();

            bindizr_db::api_token::update_last_used_at(cx.db(), stored_token.id, last_used_at)
                .await
                .map_err(|error| {
                    log::error!("Failed to update last_used_at: {error}");
                    ServiceError::internal_with_source("failed to update last_used_at", error)
                })?;

            ApiToken {
                last_used_at: Some(last_used_at),
                ..stored_token
            }
        };

        let grants = bindizr_db::role_grant::list_by_role_id(cx.db(), token.role_id).await?;

        Ok((Self::from_token(&token, grants), token))
    }

    /// Preload the grants of a key whose signature verified, as
    /// `authenticate_token` does for a token.
    pub async fn authenticate_tsig_key(
        cx: &Context,
        tsig_key: &TsigKey,
    ) -> Result<Self, ServiceError> {
        let grants = bindizr_db::role_grant::list_by_role_id(cx.db(), tsig_key.role_id).await?;
        Ok(Self::from_tsig_key(tsig_key, grants))
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
            "role does not permit '{action}' in all zones"
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
            "role does not permit '{action}' in zone '{}'",
            zone.name
        )))
    }

    /// Return the role whose grants bound the caller's visibility; `None` means
    /// unrestricted. List queries join it against the grants in SQL.
    pub(crate) fn scope_role_id(&self) -> Option<RoleId> {
        match &self.scope {
            CallerScope::Global => None,
            CallerScope::Role { id, .. } => Some(*id),
        }
    }

    /// Return the grants that bound the caller, or `None` when nothing does.
    pub(crate) fn grants(&self) -> Option<&RoleGrants> {
        match &self.scope {
            CallerScope::Global => None,
            CallerScope::Role { grants, .. } => Some(grants),
        }
    }

    /// Return whether the caller may see `zone_id`: any grant reaching it, whatever its actions.
    pub(crate) fn sees_zone(&self, zone_id: ZoneId) -> bool {
        self.grants()
            .is_none_or(|grants| grants.reaches_zone(zone_id))
    }

    /// Authorize the zone's visibility: 404 for zones the caller cannot see,
    /// so a role cannot probe zone existence.
    pub(crate) fn authorize_zone_visible(&self, zone: &Zone) -> Result<(), ServiceError> {
        if self.sees_zone(zone.id) {
            return Ok(());
        }

        Err(ServiceError::zone_not_found(&zone.name))
    }

    /// Re-read the credential and grants in `tx`, after locking the zone.
    /// Shared row locks or SQLite's writer reservation serialize revocation with writes.
    pub(crate) async fn reauthenticate_tx(
        &self,
        tx: &mut Transaction<'_>,
    ) -> Result<Self, ServiceError> {
        let (role_id, credential) = match &self.scope {
            CallerScope::Global => return Ok(self.clone()),
            CallerScope::Role {
                credential: Credential::TsigKey(tsig_key_id),
                ..
            } => {
                // Lock the key so deletion waits for this transaction.
                let tsig_key = bindizr_db::tsig_key::get_tx(tx, *tsig_key_id, LockLevel::Shared)
                    .await?
                    .ok_or_else(|| ServiceError::invalid_token("TSIG key no longer exists"))?;
                (tsig_key.role_id, Credential::TsigKey(tsig_key.id))
            }
            CallerScope::Role {
                credential: Credential::Token(token_id),
                ..
            } => {
                let token = bindizr_db::api_token::get_tx(tx, *token_id, LockLevel::Shared)
                    .await?
                    .filter(|token| {
                        token
                            .expires_at
                            .is_none_or(|expires_at| Utc::now() < expires_at)
                    })
                    .ok_or_else(|| ServiceError::invalid_token("invalid or expired token"))?;

                (token.role_id, Credential::Token(token.id))
            }
        };
        let grants =
            bindizr_db::role_grant::list_by_role_id_tx(tx, role_id, LockLevel::Shared).await?;

        Ok(Self {
            scope: CallerScope::Role {
                id: role_id,
                credential,
                grants: grants.into(),
            },
            origin: self.origin.clone(),
        })
    }

    /// Authorize record reads and writes in `zone`; a zone no grant reaches
    /// reads as `NotFound`.
    pub(crate) fn authorize_record_access(
        &self,
        zone: &Zone,
        writes: &[RecordAccess],
    ) -> Result<(), ServiceError> {
        let Some(grants) = self.grants() else {
            return Ok(());
        };

        // Ahead of the per-write loop, which a batch resolving to no writes
        // would otherwise pass vacuously.
        if !grants.reaches_zone(zone.id) {
            return Err(ServiceError::zone_not_found(&zone.name));
        }

        authorize_with_grants(grants, zone, writes)
    }

    /// Return whether `record:read` or the write `action` covers a record of this
    /// name and type, so a write-only grant finds what it may change.
    pub(crate) fn reaches_record(
        &self,
        action: Action,
        zone_id: ZoneId,
        owner: &OwnerName,
        record_type: Option<RecordType>,
    ) -> bool {
        self.grants()
            .is_none_or(|grants| grants.reaches_record(action, zone_id, owner, record_type))
    }

    /// Return whether a `record:read` grant covers a record of this name and type.
    pub(crate) fn sees_record(
        &self,
        zone_id: ZoneId,
        owner: &OwnerName,
        record_type: Option<RecordType>,
    ) -> bool {
        self.grants().is_none_or(|grants| {
            grants.covers_record(Action::RecordRead, zone_id, owner, record_type)
        })
    }

    /// Return the records a `record:read` grant covers; the rest are dropped, so a
    /// write-only grant learns what it writes and nothing already there.
    pub(crate) fn readable_records<T: GrantedRecord>(
        &self,
        zone_id: ZoneId,
        records: impl IntoIterator<Item = T>,
    ) -> ReadableRecords<T> {
        ReadableRecords(
            records
                .into_iter()
                .filter(|record| {
                    self.sees_record(zone_id, record.name(), Some(record.record_type()))
                })
                .collect(),
        )
    }

    /// Return the record actions the caller may take on one record, so a client
    /// offers exactly the ones the service would allow.
    pub(crate) fn record_actions(
        &self,
        zone_id: ZoneId,
        owner: &OwnerName,
        record_type: RecordType,
    ) -> Vec<Action> {
        [
            Action::RecordRead,
            Action::RecordUpdate,
            Action::RecordDelete,
        ]
        .into_iter()
        .filter(|&action| {
            self.grants().is_none_or(|grants| {
                grants.covers_record(action, zone_id, owner, Some(record_type))
            })
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
            "role does not permit '{action}' over all zones whole"
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
            "role does not permit '{action}' over zone '{}' whole",
            zone.name
        )))
    }
}

/// Which resources the caller may access; transport and credential names do not decide it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CallerScope {
    Global,
    /// A role's caller, through the credential that authenticated it.
    Role {
        id: RoleId,
        credential: Credential,
        grants: RoleGrants,
    },
}

/// The credential a role's caller proved itself with, re-read by every
/// transaction that acts for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Credential {
    Token(TokenId),
    TsigKey(TsigKeyId),
}

/// One record action to authorize, its owner relative to the zone (stored
/// form). A `None` type matches only grants that constrain no type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordAccess {
    pub(crate) action: Action,
    pub(crate) relative_name: OwnerName,
    pub(crate) record_type: Option<RecordType>,
}

/// A record as grants see it: an owner name and a type.
pub(crate) trait GrantedRecord {
    /// Return the owner name, relative to its zone (stored form).
    fn name(&self) -> &OwnerName;

    /// Return the record's type.
    fn record_type(&self) -> RecordType;
}

impl GrantedRecord for Record {
    /// Return the stored owner name.
    fn name(&self) -> &OwnerName {
        &self.name
    }

    /// Return the stored type.
    fn record_type(&self) -> RecordType {
        self.record_type
    }
}

impl GrantedRecord for RecordData {
    /// Return the owner name.
    fn name(&self) -> &OwnerName {
        &self.name
    }

    /// Return the type.
    fn record_type(&self) -> RecordType {
        self.record_type
    }
}

/// Zone records authorized by [`Caller::readable_records`] or [`WholeZoneRead`].
/// Responses render existing records only through this checked type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReadableRecords<T>(Vec<T>);

impl<T> ReadableRecords<T> {
    /// Add a record the caller is writing: what it sends is its own to see.
    pub(crate) fn push_written(&mut self, record: T) {
        self.0.push(record);
    }

    /// Return the readable records.
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
    /// Return every record of the zone, unfiltered: the proof covers them all.
    pub(crate) fn readable_records<T>(self, records: Vec<T>) -> ReadableRecords<T> {
        ReadableRecords(records)
    }
}

/// Authorize every action at its name and type against the supplied grants.
fn authorize_with_grants(
    grants: &RoleGrants,
    zone: &Zone,
    writes: &[RecordAccess],
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
                    .map_or("records".to_string(), |record_type| record_type.to_string()),
                zone.name
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests;
