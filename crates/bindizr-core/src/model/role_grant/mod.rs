use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use thiserror::Error;
use utoipa::ToSchema;

use crate::dns::name::{OwnerName, ZoneName};
use crate::model::grant_pattern;
use crate::model::grant_pattern::MATCH_ANY;
use crate::model::record::RecordType;
use crate::model::role::RoleId;
use crate::model::zone::ZoneId;

id_newtype!(
    /// The id of a role grant row.
    RoleGrantId
);

/// An action name outside the closed set a grant can hold.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unsupported action '{value}' (supported: {})", Action::supported_names().join(", "))]
pub struct ParseActionError {
    pub value: String,
}

/// One operation a grant permits, spelled `<resource>:<action>`:
///
/// - `zone:read` — read a zone's status and version history
/// - `zone:create` — create zones, and with `zone:update` rename one; all zones only
/// - `zone:update` — change zone settings (including nsupdate SOA) and send NOTIFY; with unnarrowed
///   `record:read`, `record:create` and `record:delete`, roll back a version
/// - `zone:delete` — delete zones
/// - `zone:transfer` — answer a TSIG-signed AXFR/IXFR; TSIG keys only
/// - `record:read` — list and read records; with no name or type limit, also
///   export the zone and read its versions and diffs
/// - `record:create` — add records, including by import, nsupdate and ExternalDNS
/// - `record:update` — change a record in place; without `record:read` on it,
///   every field must be given; also required when nsupdate changes existing records' TTL
/// - `record:delete` — delete records, including by nsupdate and ExternalDNS; also required
///   when nsupdate replaces a CNAME, DNAME, or matching WKS record
/// - `dnssec:read` — read DNSSEC status and check the parent DS; in all zones,
///   also read signing policies
/// - `dnssec:manage` — enable, disable and re-sign, manage keys and rollovers;
///   in all zones, also change signing policies
/// - `secondary:read` — list and read secondaries; all zones only
/// - `secondary:manage` — register, change, check and remove secondaries; all zones only
/// - `access:manage` — manage roles, API tokens and TSIG keys; all zones only,
///   and equivalent to admin since its holder can grant itself anything
/// - `log:read` — read the audit, access and transfer logs; all zones only
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema,
)]
pub enum Action {
    #[serde(rename = "zone:read")]
    ZoneRead,
    #[serde(rename = "zone:create")]
    ZoneCreate,
    #[serde(rename = "zone:update")]
    ZoneUpdate,
    #[serde(rename = "zone:delete")]
    ZoneDelete,
    #[serde(rename = "zone:transfer")]
    ZoneTransfer,
    #[serde(rename = "record:read")]
    RecordRead,
    #[serde(rename = "record:create")]
    RecordCreate,
    #[serde(rename = "record:update")]
    RecordUpdate,
    #[serde(rename = "record:delete")]
    RecordDelete,
    #[serde(rename = "dnssec:read")]
    DnssecRead,
    #[serde(rename = "dnssec:manage")]
    DnssecManage,
    #[serde(rename = "secondary:read")]
    SecondaryRead,
    #[serde(rename = "secondary:manage")]
    SecondaryManage,
    #[serde(rename = "access:manage")]
    AccessManage,
    #[serde(rename = "log:read")]
    LogRead,
}

impl Action {
    /// Every action, in storage order.
    pub const ALL: [Self; 15] = [
        Self::ZoneRead,
        Self::ZoneCreate,
        Self::ZoneUpdate,
        Self::ZoneDelete,
        Self::ZoneTransfer,
        Self::RecordRead,
        Self::RecordCreate,
        Self::RecordUpdate,
        Self::RecordDelete,
        Self::DnssecRead,
        Self::DnssecManage,
        Self::SecondaryRead,
        Self::SecondaryManage,
        Self::AccessManage,
        Self::LogRead,
    ];

    /// Return the canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ZoneRead => "zone:read",
            Self::ZoneCreate => "zone:create",
            Self::ZoneUpdate => "zone:update",
            Self::ZoneDelete => "zone:delete",
            Self::ZoneTransfer => "zone:transfer",
            Self::RecordRead => "record:read",
            Self::RecordCreate => "record:create",
            Self::RecordUpdate => "record:update",
            Self::RecordDelete => "record:delete",
            Self::DnssecRead => "dnssec:read",
            Self::DnssecManage => "dnssec:manage",
            Self::SecondaryRead => "secondary:read",
            Self::SecondaryManage => "secondary:manage",
            Self::AccessManage => "access:manage",
            Self::LogRead => "log:read",
        }
    }

    /// Return whether the action targets nothing a zone owns, so only an all-zones
    /// grant carries it.
    pub fn needs_all_zones(self) -> bool {
        matches!(
            self,
            Self::ZoneCreate
                | Self::SecondaryRead
                | Self::SecondaryManage
                | Self::AccessManage
                | Self::LogRead
        )
    }

    /// Return whether a grant's name and type constraints narrow this action.
    pub fn is_record_action(self) -> bool {
        matches!(
            self,
            Self::RecordRead | Self::RecordCreate | Self::RecordUpdate | Self::RecordDelete
        )
    }

    /// List the names an action parses from, for messages that list them.
    pub fn supported_names() -> Vec<&'static str> {
        Self::ALL.into_iter().map(Self::as_str).collect()
    }
}

impl fmt::Display for Action {
    /// Write the action in its storage form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Action {
    type Err = ParseActionError;

    /// Parse an action from its storage form, ignoring case.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|action| action.as_str().eq_ignore_ascii_case(value))
            .ok_or_else(|| ParseActionError {
                value: value.to_string(),
            })
    }
}

/// The actions one grant permits, stored as a comma-separated list in
/// [`Action::ALL`] order so one set has one spelling.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ActionSet(BTreeSet<Action>);

impl ActionSet {
    /// Return whether the set permits `action`.
    pub fn contains(&self, action: Action) -> bool {
        self.0.contains(&action)
    }

    /// Return whether the set permits nothing.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate the actions in storage order.
    pub fn iter(&self) -> impl Iterator<Item = Action> + '_ {
        self.0.iter().copied()
    }
}

impl FromIterator<Action> for ActionSet {
    /// Collect actions into a set, dropping repeats.
    fn from_iter<I: IntoIterator<Item = Action>>(actions: I) -> Self {
        Self(actions.into_iter().collect())
    }
}

impl fmt::Display for ActionSet {
    /// Write the set in its comma-separated row form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, action) in self.iter().enumerate() {
            if index > 0 {
                f.write_str(",")?;
            }
            f.write_str(action.as_str())?;
        }

        Ok(())
    }
}

impl TryFrom<String> for ActionSet {
    type Error = ParseActionError;

    /// Read the comma-separated row form.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value
            .split(',')
            .filter(|action| !action.is_empty())
            .map(str::parse)
            .collect()
    }
}

impl<DB: sqlx::Database> sqlx::Type<DB> for ActionSet
where
    String: sqlx::Type<DB>,
{
    /// Return the SQL type used to store this value.
    fn type_info() -> DB::TypeInfo {
        <String as sqlx::Type<DB>>::type_info()
    }

    /// Return whether the SQL type can store this value.
    fn compatible(ty: &DB::TypeInfo) -> bool {
        <String as sqlx::Type<DB>>::compatible(ty)
    }
}

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for ActionSet
where
    String: sqlx::Encode<'q, DB>,
{
    /// Encode this value using its database representation.
    fn encode_by_ref(
        &self,
        buffer: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<IsNull, BoxDynError> {
        self.to_string().encode_by_ref(buffer)
    }
}

/// Which zones a grant reaches: all zones, including ones created later
/// (row `zone_id` NULL), or one zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleZoneScope {
    All,
    Zone(ZoneId),
}

impl RoleZoneScope {
    /// Return the row form: `None` for all zones.
    pub fn zone_id(self) -> Option<ZoneId> {
        match self {
            Self::All => None,
            Self::Zone(zone_id) => Some(zone_id),
        }
    }

    /// Return whether the scope reaches `zone_id`.
    pub fn covers(self, zone_id: ZoneId) -> bool {
        match self {
            Self::All => true,
            Self::Zone(scoped) => scoped == zone_id,
        }
    }
}

impl From<Option<ZoneId>> for RoleZoneScope {
    /// Read the row form, where NULL means all zones.
    fn from(zone_id: Option<ZoneId>) -> Self {
        zone_id.map_or(Self::All, Self::Zone)
    }
}

/// A role's actions and zone scope; name/type patterns narrow only `record:*`.
/// Pattern syntax is defined by [`crate::model::grant_pattern`].
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct RoleGrant {
    pub id: RoleGrantId,
    pub role_id: RoleId,
    #[sqlx(rename = "zone_id", try_from = "Option<ZoneId>")]
    pub zone_scope: RoleZoneScope,
    #[sqlx(try_from = "String")]
    pub actions: ActionSet,
    pub record_name_pattern: String,
    pub record_types: String,
    pub created_at: DateTime<Utc>,
}

// Private: `RoleGrants` answers every question over the union of grants.
impl RoleGrant {
    /// Return whether this grant reaches `zone_id` with `action`.
    fn permits(&self, action: Action, zone_id: ZoneId) -> bool {
        self.actions.contains(action) && self.zone_scope.covers(zone_id)
    }

    /// Return whether this grant's record constraints cover `record_type` at the
    /// relative owner name.
    fn matches(&self, owner: &OwnerName, record_type: Option<RecordType>) -> bool {
        grant_pattern::matches_name(&self.record_name_pattern, owner)
            && grant_pattern::matches_types(&self.record_types, record_type)
    }

    /// Return whether this grant covers every name `pattern` matches, for `record_type`.
    fn covers_pattern(&self, pattern: &str, record_type: RecordType) -> bool {
        grant_pattern::has_pattern_coverage(&self.record_name_pattern, pattern)
            && grant_pattern::matches_types(&self.record_types, Some(record_type))
    }

    /// Return whether this grant constrains no name or type.
    fn is_unrestricted(&self) -> bool {
        self.record_name_pattern == MATCH_ANY && self.record_types == MATCH_ANY
    }
}

/// A role's grants, whose rights are their union.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RoleGrants(Arc<[RoleGrant]>);

impl RoleGrants {
    /// Return whether an all-zones grant carries `action`, as what no zone owns needs.
    pub fn permits_all_zones(&self, action: Action) -> bool {
        self.0
            .iter()
            .any(|grant| grant.zone_scope == RoleZoneScope::All && grant.actions.contains(action))
    }

    /// Return whether an all-zones grant carries `action` with no name or type limit.
    pub fn covers_all_whole_zones(&self, action: Action) -> bool {
        self.0.iter().any(|grant| {
            grant.zone_scope == RoleZoneScope::All
                && grant.actions.contains(action)
                && grant.is_unrestricted()
        })
    }

    /// Return whether some grant reaches `zone_id` with `action`.
    pub fn permits(&self, action: Action, zone_id: ZoneId) -> bool {
        self.0.iter().any(|grant| grant.permits(action, zone_id))
    }

    /// Return whether some grant reaches `zone_id`, whatever its actions.
    pub fn reaches_zone(&self, zone_id: ZoneId) -> bool {
        self.0.iter().any(|grant| grant.zone_scope.covers(zone_id))
    }

    /// Return whether some grant permits `action` on a record of this name and type.
    pub fn covers_record(
        &self,
        action: Action,
        zone_id: ZoneId,
        owner: &OwnerName,
        record_type: Option<RecordType>,
    ) -> bool {
        self.0
            .iter()
            .any(|grant| grant.permits(action, zone_id) && grant.matches(owner, record_type))
    }

    /// Return whether `record:read` or the write `action` covers a record of this
    /// name and type, so a write-only grant finds what it may change.
    pub fn reaches_record(
        &self,
        action: Action,
        zone_id: ZoneId,
        owner: &OwnerName,
        record_type: Option<RecordType>,
    ) -> bool {
        self.covers_record(Action::RecordRead, zone_id, owner, record_type)
            || self.covers_record(action, zone_id, owner, record_type)
    }

    /// Return whether some grant permits `action` in `zone_id` with no name or type limit.
    pub fn covers_whole_zone(&self, action: Action, zone_id: ZoneId) -> bool {
        self.0
            .iter()
            .any(|grant| grant.permits(action, zone_id) && grant.is_unrestricted())
    }

    /// List the grant patterns in `zone_id` where the role's grants together hold
    /// every one of `actions` for one of `record_types`.
    pub fn patterns_holding(
        &self,
        zone_id: ZoneId,
        actions: &[Action],
        record_types: &[RecordType],
    ) -> BTreeSet<&str> {
        // Patterns nest or are disjoint, so grants meet only on their own patterns.
        self.0
            .iter()
            .filter(|grant| grant.zone_scope.covers(zone_id))
            .map(|grant| grant.record_name_pattern.as_str())
            .filter(|pattern| {
                record_types.iter().any(|record_type| {
                    actions.iter().all(|&action| {
                        self.0.iter().any(|grant| {
                            grant.permits(action, zone_id)
                                && grant.covers_pattern(pattern, *record_type)
                        })
                    })
                })
            })
            .collect()
    }
}

impl From<Vec<RoleGrant>> for RoleGrants {
    /// Wrap a role's loaded grants.
    fn from(grants: Vec<RoleGrant>) -> Self {
        Self(grants.into())
    }
}

/// A grant joined with its zone name; an all-zones grant has no zone name.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct RoleGrantWithZone {
    #[sqlx(flatten)]
    pub grant: RoleGrant,
    pub zone_name: Option<ZoneName>,
}

#[cfg(test)]
mod tests;
