use std::{collections::BTreeSet, fmt, str::FromStr, sync::Arc};

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use thiserror::Error;

use crate::{
    dns::name::OwnerName,
    model::{
        grant_pattern::{MATCH_ANY, matches_name, matches_types},
        record::RecordType,
        role::RoleId,
        zone::ZoneId,
    },
};

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
/// - `zone:create` — create zones; every zone only
/// - `zone:update` — change a zone's settings, send NOTIFY, roll back a version
/// - `zone:delete` — delete zones
/// - `zone:transfer` — answer a TSIG-signed AXFR/IXFR; TSIG keys only
/// - `record:read` — list and read records; with no name or type limit, also
///   export the zone and read its versions and diffs
/// - `record:create` — add records, including by import, nsupdate and ExternalDNS
/// - `record:update` — change a record in place
/// - `record:delete` — delete records, including by nsupdate and ExternalDNS
/// - `dnssec:read` — read DNSSEC status and check the parent DS; in every zone,
///   also read signing policies
/// - `dnssec:manage` — enable, disable and re-sign, manage keys and rollovers;
///   in every zone, also change signing policies
/// - `secondary:read` — list secondaries and the transfers served them; every zone only
/// - `secondary:manage` — register, change, check and remove secondaries; every zone only
/// - `access:manage` — manage roles, API tokens and TSIG keys; every zone only,
///   and equivalent to admin since its holder can grant itself anything
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
    utoipa::ToSchema,
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
}

impl Action {
    /// Every action, in storage order.
    pub const ALL: [Action; 14] = [
        Action::ZoneRead,
        Action::ZoneCreate,
        Action::ZoneUpdate,
        Action::ZoneDelete,
        Action::ZoneTransfer,
        Action::RecordRead,
        Action::RecordCreate,
        Action::RecordUpdate,
        Action::RecordDelete,
        Action::DnssecRead,
        Action::DnssecManage,
        Action::SecondaryRead,
        Action::SecondaryManage,
        Action::AccessManage,
    ];

    /// Storage and API form.
    pub fn as_str(self) -> &'static str {
        match self {
            Action::ZoneRead => "zone:read",
            Action::ZoneCreate => "zone:create",
            Action::ZoneUpdate => "zone:update",
            Action::ZoneDelete => "zone:delete",
            Action::ZoneTransfer => "zone:transfer",
            Action::RecordRead => "record:read",
            Action::RecordCreate => "record:create",
            Action::RecordUpdate => "record:update",
            Action::RecordDelete => "record:delete",
            Action::DnssecRead => "dnssec:read",
            Action::DnssecManage => "dnssec:manage",
            Action::SecondaryRead => "secondary:read",
            Action::SecondaryManage => "secondary:manage",
            Action::AccessManage => "access:manage",
        }
    }

    /// Whether the action targets nothing a zone owns, so only an all-zones grant carries it.
    pub fn needs_all_zones(self) -> bool {
        matches!(
            self,
            Action::ZoneCreate
                | Action::SecondaryRead
                | Action::SecondaryManage
                | Action::AccessManage
        )
    }

    /// Whether a grant's name and type constraints narrow this action.
    pub fn is_record_action(self) -> bool {
        matches!(
            self,
            Action::RecordRead | Action::RecordCreate | Action::RecordUpdate | Action::RecordDelete
        )
    }

    /// The names an action parses from, for messages that list them.
    pub fn supported_names() -> Vec<&'static str> {
        Self::ALL.iter().map(|action| action.as_str()).collect()
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
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct ActionSet(BTreeSet<Action>);

impl ActionSet {
    /// Whether the set permits `action`.
    pub fn contains(&self, action: Action) -> bool {
        self.0.contains(&action)
    }

    /// Whether the set permits nothing.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The actions in storage order.
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

    /// Check whether the SQL type can store this value.
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
        buf: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        self.to_string().encode_by_ref(buf)
    }
}

/// Which zones a grant reaches: every zone, including ones created later
/// (row `zone_id` NULL), or one zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleZoneScope {
    All,
    Zone(ZoneId),
}

impl RoleZoneScope {
    /// The row form: `None` for every zone.
    pub fn zone_id(self) -> Option<ZoneId> {
        match self {
            RoleZoneScope::All => None,
            RoleZoneScope::Zone(zone_id) => Some(zone_id),
        }
    }

    /// Whether the scope reaches `zone_id`.
    pub fn covers(self, zone_id: ZoneId) -> bool {
        match self {
            RoleZoneScope::All => true,
            RoleZoneScope::Zone(scoped) => scoped == zone_id,
        }
    }
}

impl From<Option<ZoneId>> for RoleZoneScope {
    /// Read the row form, where NULL means every zone.
    fn from(zone_id: Option<ZoneId>) -> Self {
        zone_id.map_or(RoleZoneScope::All, RoleZoneScope::Zone)
    }
}

/// One grant of a role: the actions it permits in its zone scope. The name
/// pattern and type list, in [`super::grant_pattern`] syntax, narrow its
/// `record:*` actions only.
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
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
    /// Whether this grant reaches `zone_id` with `action`.
    fn permits(&self, action: Action, zone_id: ZoneId) -> bool {
        self.actions.contains(action) && self.zone_scope.covers(zone_id)
    }

    /// Whether this grant's record constraints cover `record_type` at the
    /// relative owner name.
    fn matches(&self, name: &OwnerName, record_type: Option<&RecordType>) -> bool {
        matches_name(&self.record_name_pattern, name)
            && matches_types(&self.record_types, record_type)
    }

    /// Whether this grant constrains no name or type.
    fn is_unrestricted(&self) -> bool {
        self.record_name_pattern == MATCH_ANY && self.record_types == MATCH_ANY
    }
}

/// A role's grants, whose rights are their union.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RoleGrants(Arc<[RoleGrant]>);

impl From<Vec<RoleGrant>> for RoleGrants {
    /// Wrap a role's loaded grants.
    fn from(grants: Vec<RoleGrant>) -> Self {
        RoleGrants(grants.into())
    }
}

impl RoleGrants {
    /// Whether the role holds no grant.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The grants themselves.
    pub fn iter(&self) -> impl Iterator<Item = &RoleGrant> {
        self.0.iter()
    }

    /// Whether an all-zones grant carries `action`, as what no zone owns needs.
    pub fn permits_everywhere(&self, action: Action) -> bool {
        self.0
            .iter()
            .any(|grant| grant.zone_scope == RoleZoneScope::All && grant.actions.contains(action))
    }

    /// Whether an all-zones grant carries `action` with no name or type limit.
    pub fn covers_every_zone_whole(&self, action: Action) -> bool {
        self.0.iter().any(|grant| {
            grant.zone_scope == RoleZoneScope::All
                && grant.actions.contains(action)
                && grant.is_unrestricted()
        })
    }

    /// Whether some grant reaches `zone_id` with `action`.
    pub fn permits(&self, action: Action, zone_id: ZoneId) -> bool {
        self.0.iter().any(|grant| grant.permits(action, zone_id))
    }

    /// Whether some grant reaches `zone_id`, whatever its actions.
    pub fn reaches_zone(&self, zone_id: ZoneId) -> bool {
        self.0.iter().any(|grant| grant.zone_scope.covers(zone_id))
    }

    /// Whether some grant permits `action` on a record of this name and type.
    pub fn covers_record(
        &self,
        action: Action,
        zone_id: ZoneId,
        name: &OwnerName,
        record_type: Option<&RecordType>,
    ) -> bool {
        self.0
            .iter()
            .any(|grant| grant.permits(action, zone_id) && grant.matches(name, record_type))
    }

    /// Whether `record:read` or the write `action` covers a record of this
    /// name and type, so a write-only grant finds what it may change.
    pub fn reaches_record(
        &self,
        action: Action,
        zone_id: ZoneId,
        name: &OwnerName,
        record_type: Option<&RecordType>,
    ) -> bool {
        self.covers_record(Action::RecordRead, zone_id, name, record_type)
            || self.covers_record(action, zone_id, name, record_type)
    }

    /// Whether some grant permits `action` in `zone_id` with no name or type limit.
    pub fn covers_whole_zone(&self, action: Action, zone_id: ZoneId) -> bool {
        self.0
            .iter()
            .any(|grant| grant.permits(action, zone_id) && grant.is_unrestricted())
    }

    /// The patterns in `zone_id` whose grants, with those of `*`, hold all `actions`.
    pub fn patterns_holding(&self, zone_id: ZoneId, actions: &[Action]) -> BTreeSet<&str> {
        let reaching: Vec<&RoleGrant> = self
            .0
            .iter()
            .filter(|grant| grant.zone_scope.covers(zone_id))
            .collect();
        reaching
            .iter()
            .map(|grant| grant.record_name_pattern.as_str())
            .filter(|pattern| {
                actions.iter().all(|&action| {
                    reaching.iter().any(|grant| {
                        grant.actions.contains(action)
                            && (grant.record_name_pattern == *pattern
                                || grant.record_name_pattern == MATCH_ANY)
                    })
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
