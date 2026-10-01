//! Zone request, patch, filter, and response payloads.

use bindizr_core::{
    dns::{Serial, SoaInterval, Ttl},
    model::zone::ZoneId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::secondary::TransferResponse;
use crate::{model::zone::Zone, notify::NotifyTarget};

/// Which records a zone reads back as: the user records alone, or with the
/// derived DNSSEC records bindizr generates.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ZoneView {
    Plain,
    Signed,
}

impl ZoneView {
    /// The view a `signed` flag asks for.
    pub fn from_signed(signed: bool) -> Self {
        if signed {
            ZoneView::Signed
        } else {
            ZoneView::Plain
        }
    }
}

/// Whether a manual NOTIFY bumps the zone serial first, so secondaries
/// transfer even when nothing changed.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NotifySerial {
    Keep,
    Bump,
}

impl NotifySerial {
    /// The bump a `bump_serial` flag asks for.
    pub fn from_bump_serial(bump_serial: bool) -> Self {
        if bump_serial {
            NotifySerial::Bump
        } else {
            NotifySerial::Keep
        }
    }
}

/// API representation of a zone.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct GetZoneResponse {
    /// Absent on a dry run, where nothing was written to carry one.
    #[schema(example = 1, value_type = Option<i32>)]
    pub id: Option<ZoneId>,
    #[schema(example = "example.com")]
    pub name: String,
    #[schema(example = "ns1.example.com")]
    pub mname: String,
    #[schema(example = "admin@example.com")]
    pub rname: String,
    #[schema(example = 3600, value_type = i32)]
    pub default_ttl: Ttl,
    #[schema(example = 42, value_type = u32)]
    pub serial: Serial,
    #[schema(example = 7200, value_type = i32)]
    pub refresh: SoaInterval,
    #[schema(example = 3600, value_type = i32)]
    pub retry: SoaInterval,
    #[schema(example = 604800, value_type = i32)]
    pub expire: SoaInterval,
    #[schema(example = 3600, value_type = i32)]
    pub minimum_ttl: Ttl,
    /// Whether the DNS plane serves the zone. A disabled one stays editable but
    /// leaves the catalog and answers no transfer, so secondaries drop it.
    #[schema(example = true)]
    pub enabled: bool,
    pub description: Option<String>,
}

impl From<&Zone> for GetZoneResponse {
    /// Build a zone response from its stored settings.
    fn from(zone: &Zone) -> Self {
        GetZoneResponse {
            id: zone.id.written(),
            name: zone.name.to_string(),
            mname: zone.mname.clone(),
            rname: zone.rname.clone(),
            default_ttl: zone.default_ttl,
            serial: zone.serial,
            refresh: zone.refresh,
            retry: zone.retry,
            expire: zone.expire,
            minimum_ttl: zone.minimum_ttl,
            enabled: zone.enabled,
            description: zone.description.clone(),
        }
    }
}

/// Request body for creating a zone.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateZoneRequest {
    #[schema(example = "example.com")]
    pub name: String,
    #[schema(example = "ns1.example.com")]
    pub mname: String,
    #[schema(example = "admin@example.com")]
    pub rname: String,
    /// Record TTL the zone hands out when a record names none; defaults to
    /// `dns.zone_defaults.ttl`.
    #[schema(example = 3600)]
    pub default_ttl: Option<i32>,
    /// Starting serial, auto-generated if not provided. Must be 1-2137483647 so the counter keeps room to advance, and can only be set at creation.
    #[schema(example = 42, value_type = Option<u32>)]
    pub serial: Option<Serial>,
    #[schema(example = 7200)]
    pub refresh: Option<i32>,
    #[schema(example = 3600)]
    pub retry: Option<i32>,
    #[schema(example = 604800)]
    pub expire: Option<i32>,
    #[schema(example = 3600)]
    pub minimum_ttl: Option<i32>,
    /// Free-text note for operators, at most 255 characters.
    #[schema(example = "customer A, migrated 2026-01")]
    pub description: Option<String>,
    /// Start the zone with an apex NS record naming the SOA MNAME; false
    /// leaves every NS record to the caller.
    #[serde(default = "default_apex_ns")]
    #[schema(example = true)]
    pub apex_ns: bool,
    /// Validate and report the change without writing it.
    #[serde(default)]
    #[schema(example = false)]
    pub dry_run: bool,
}

/// Create the apex NS record when a request leaves the choice out.
fn default_apex_ns() -> bool {
    true
}

/// Query filters and pagination for listing zones.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct GetZonesFilter {
    /// Filter by zone name.
    #[schema(example = "example.com")]
    pub name: Option<String>,
    /// Filter by zone ID.
    #[schema(example = 1, value_type = Option<i32>)]
    #[param(value_type = Option<i32>)]
    pub id: Option<ZoneId>,
    /// Filter by mname.
    #[schema(example = "ns1.example.com")]
    pub mname: Option<String>,
    /// Filter by rname.
    #[schema(example = "admin@example.com")]
    pub rname: Option<String>,
    /// Filter by default TTL.
    #[schema(example = 3600)]
    pub default_ttl: Option<i32>,
    /// Filter by minimum default TTL.
    #[schema(example = 300)]
    pub min_default_ttl: Option<i32>,
    /// Filter by maximum default TTL.
    #[schema(example = 86400)]
    pub max_default_ttl: Option<i32>,
    /// Filter by serial.
    #[schema(example = 42, value_type = Option<u32>)]
    #[param(value_type = Option<u32>)]
    pub serial: Option<Serial>,
    /// Filter by minimum serial.
    #[schema(example = 1, value_type = Option<u32>)]
    #[param(value_type = Option<u32>)]
    pub min_serial: Option<Serial>,
    /// Filter by maximum serial.
    #[schema(example = 99, value_type = Option<u32>)]
    #[param(value_type = Option<u32>)]
    pub max_serial: Option<Serial>,
    /// Keep zones created at or after this RFC 3339 timestamp.
    pub created_after: Option<DateTime<Utc>>,
    /// Keep zones created at or before this RFC 3339 timestamp.
    pub created_before: Option<DateTime<Utc>>,
    /// `true` keeps the zones signing under a DNSSEC policy, `false` the rest.
    #[schema(example = true)]
    pub signed: Option<bool>,
    /// `true` keeps the zones the DNS plane serves, `false` the disabled ones.
    #[schema(example = true)]
    pub enabled: Option<bool>,
    /// Partially search zones.
    #[schema(example = "example")]
    pub search: Option<String>,
    /// `name` (the default), `serial`, `default_ttl`, or `created_at`.
    #[schema(example = "name")]
    pub sort: Option<String>,
    /// `asc` (the default) or `desc`.
    #[schema(example = "asc")]
    pub order: Option<String>,
    /// Zones per page; defaults to 50 when omitted, 1000 is the largest page
    /// accepted.
    #[schema(example = 50)]
    pub limit: Option<u32>,
    /// Number of zones to skip.
    #[schema(example = 0)]
    pub offset: Option<u64>,
}

/// Request body for updating a zone; an omitted field keeps the current
/// value, merged inside the update transaction. `serial` is carried only to
/// be rejected: it is fixed at creation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateZoneRequest {
    /// A different name renames the zone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "example.com")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "ns1.example.com")]
    pub mname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "admin@example.com")]
    pub rname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = 3600)]
    pub default_ttl: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = 7200)]
    pub refresh: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = 3600)]
    pub retry: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = 604800)]
    pub expire: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = 3600)]
    pub minimum_ttl: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = 42)]
    pub serial: Option<u32>,
    /// `false` stops the DNS plane serving the zone without deleting it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = true)]
    pub enabled: Option<bool>,
    /// Empty clears the note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "customer A, migrated 2026-01")]
    pub description: Option<String>,
    /// Validate and report the change without writing it.
    #[serde(default)]
    #[schema(example = false)]
    pub dry_run: bool,
}

/// The success message every front end serves for a manual NOTIFY.
pub fn build_notify_message(target: NotifyTarget<'_>, serial: NotifySerial) -> String {
    let scope = match target {
        NotifyTarget::Zone(zone_name) => format!("zone: {}", zone_name),
        NotifyTarget::All => "all zones".to_string(),
    };
    let suffix = match serial {
        NotifySerial::Bump => " (serial bumped)",
        NotifySerial::Keep => "",
    };
    format!("NOTIFY sent successfully for {}{}", scope, suffix)
}

/// What deleting a zone takes with it. A dry run reports the counts and
/// removes nothing; deleting a zone cannot be undone from the tool.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct DeleteZoneResponse {
    /// Whether this call removed the zone; a dry run answers `false`.
    #[schema(example = true)]
    pub applied: bool,
    #[schema(example = false)]
    pub dry_run: bool,
    pub zone: GetZoneResponse,
    /// Records the zone holds, all of which go with it.
    #[schema(example = 1240)]
    pub records_deleted: u64,
    /// Saved versions, so the rollback history goes too.
    #[schema(example = 12)]
    pub versions_deleted: u64,
}

/// A single zone wrapped in a response envelope. A dry run answers with the
/// zone as it would stand and `applied: false`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct ZoneResponse {
    pub zone: GetZoneResponse,
}

/// What a zone write left behind. The zone's own fields are the change, so
/// unlike a record write this carries no diff.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct ZoneWriteResponse {
    /// Whether this call wrote; a dry run answers `false`.
    #[schema(example = true)]
    pub applied: bool,
    #[schema(example = false)]
    pub dry_run: bool,
    pub zone: GetZoneResponse,
}

/// A zone rendered as BIND master-file text. Only the daemon socket wraps the
/// export this way; the HTTP endpoint serves the text as its body.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ExportZoneFileResponse {
    pub zone_file: String,
}

/// How the serial a secondary serves compares with the one Bindizr serves.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecondaryStatus {
    InSync,
    Lagging,
    Ahead,
    /// The secondary answered, but Bindizr's own serial was not known.
    Reachable,
    Unreachable,
}

impl std::fmt::Display for SecondaryStatus {
    /// Write the status as a person reads it; serde spells the API form.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SecondaryStatus::InSync => "in sync",
            SecondaryStatus::Lagging => "lagging",
            SecondaryStatus::Ahead => "ahead",
            SecondaryStatus::Reachable => "reachable",
            SecondaryStatus::Unreachable => "unreachable",
        })
    }
}

/// What one secondary answered when probed for a zone's SOA, classified
/// against the serial Bindizr serves.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct SecondaryStatusResponse {
    #[schema(example = "10.0.1.10:53")]
    pub address: String,
    pub status: SecondaryStatus,
    #[schema(example = 42, value_type = Option<u32>)]
    pub visible_serial: Option<Serial>,
    pub error: Option<String>,
    /// The latest transfer of this zone Bindizr served the address.
    pub last_transfer: Option<TransferResponse>,
}

impl SecondaryStatusResponse {
    /// Whether the probed secondary serial matches this status's zone serial.
    pub fn is_in_sync(&self) -> bool {
        self.status == SecondaryStatus::InSync
    }

    /// Check whether the secondary probe failed to obtain a serial.
    pub fn is_unreachable(&self) -> bool {
        self.status == SecondaryStatus::Unreachable
    }
}

/// A zone's serial and the sync state of every enabled secondary, probed
/// live via SOA queries.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct ZoneStatusResponse {
    #[schema(example = "example.com")]
    pub zone_name: String,
    #[schema(example = 42, value_type = u32)]
    pub serial: Serial,
    pub secondaries: Vec<SecondaryStatusResponse>,
}
