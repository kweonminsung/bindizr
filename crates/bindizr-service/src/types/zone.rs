//! Zone request, patch, filter, and response payloads.

use std::fmt;

use bindizr_core::dns::{Serial, SoaInterval, Ttl};
use bindizr_core::model::zone::{Zone, ZoneId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::openapi::RefOr;
use utoipa::openapi::schema::Schema;
use utoipa::{IntoParams, ToSchema};

use crate::types::secondary::TransferResponse;

/// Which records a zone reads back as: the user records alone, or with the
/// derived DNSSEC records bindizr generates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoneView {
    Plain,
    Signed,
}

impl ZoneView {
    /// The view a `signed` flag asks for.
    pub fn from_signed(signed: bool) -> Self {
        if signed {
            Self::Signed
        } else {
            Self::Plain
        }
    }

    /// Return the canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Signed => "signed",
        }
    }
}

/// Whether a manual NOTIFY bumps the zone serial first, so secondaries
/// transfer even when nothing changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotifySerial {
    Keep,
    Bump,
}

impl NotifySerial {
    /// The bump a `bump_serial` flag asks for.
    pub fn from_bump_serial(bump_serial: bool) -> Self {
        if bump_serial {
            Self::Bump
        } else {
            Self::Keep
        }
    }

    /// Return the canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Keep => "keep",
            Self::Bump => "bump",
        }
    }
}

/// API representation of a zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ZoneResponse {
    /// Absent on a dry run, where nothing was written to carry one.
    #[schema(example = 1, value_type = Option<i32>)]
    pub id: Option<ZoneId>,
    #[schema(example = "example.com")]
    pub name: String,
    #[schema(example = "ns1.example.com")]
    pub mname: String,
    #[schema(example = "admin@example.com")]
    pub rname: String,
    #[schema(example = 3600, inline)]
    pub default_ttl: Ttl,
    #[schema(inline)]
    pub serial: Serial,
    #[schema(example = 7200, value_type = i32)]
    pub refresh: SoaInterval,
    #[schema(example = 3600, value_type = i32)]
    pub retry: SoaInterval,
    #[schema(example = 604_800, value_type = i32)]
    pub expire: SoaInterval,
    #[schema(example = 3600, inline)]
    pub minimum_ttl: Ttl,
    /// Whether the DNS plane serves the zone. A disabled one stays editable but
    /// leaves the catalog and answers no transfer, so secondaries drop it.
    #[schema(example = true)]
    pub enabled: bool,
    pub description: Option<String>,
}

impl From<&Zone> for ZoneResponse {
    /// Build zone information from its stored settings.
    fn from(zone: &Zone) -> Self {
        Self {
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
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
    #[schema(example = 3600, minimum = 60, maximum = 604_800)]
    pub default_ttl: Option<i64>,
    /// Starting serial, auto-generated if not provided. Accepts 0-4294967295, advances modulo 2^32, and can only be set at creation.
    #[schema(inline)]
    pub serial: Option<Serial>,
    #[schema(example = 7200)]
    pub refresh: Option<i32>,
    #[schema(example = 3600)]
    pub retry: Option<i32>,
    #[schema(example = 604_800)]
    pub expire: Option<i32>,
    #[schema(schema_with = build_minimum_ttl_schema)]
    pub minimum_ttl: Option<i64>,
    /// Free-text note for operators, at most 255 characters.
    #[schema(example = "customer A, migrated 2026-01")]
    pub description: Option<String>,
    /// Start with apex NS naming MNAME; false creates a disabled zone.
    /// Add apex NS before explicitly enabling a zone created without it.
    #[serde(default = "default_apex_ns")]
    #[schema(default = true, example = true)]
    pub apex_ns: bool,
    /// Validate and report the change without writing it.
    #[serde(default)]
    #[schema(example = false)]
    pub dry_run: bool,
}

/// Describe the nullable nonnegative SOA minimum accepted by zone writes.
fn build_minimum_ttl_schema() -> RefOr<Schema> {
    use utoipa::openapi::schema::{KnownFormat, ObjectBuilder, SchemaFormat, SchemaType, Type};

    ObjectBuilder::new()
        .schema_type(SchemaType::from_iter([Type::Integer, Type::Null]))
        .format(Some(SchemaFormat::KnownFormat(KnownFormat::Int64)))
        .minimum(Some(0u64))
        .maximum(Some(u64::from(Ttl::MAX.as_secs())))
        .examples([3600])
        .into()
}

/// Create the apex NS record when a request leaves the choice out.
fn default_apex_ns() -> bool {
    true
}

/// Query filters and pagination for listing zones.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct ZoneFilter {
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
    #[schema(example = 3600, value_type = Option<Ttl>, inline)]
    #[param(value_type = Option<Ttl>, inline)]
    pub default_ttl: Option<i64>,
    /// Filter by minimum default TTL.
    #[schema(example = 300, value_type = Option<Ttl>, inline)]
    #[param(value_type = Option<Ttl>, inline)]
    pub min_default_ttl: Option<i64>,
    /// Filter by maximum default TTL.
    #[schema(example = 86400, value_type = Option<Ttl>, inline)]
    #[param(value_type = Option<Ttl>, inline)]
    pub max_default_ttl: Option<i64>,
    /// Filter by serial.
    #[schema(inline)]
    #[param(inline)]
    pub serial: Option<Serial>,
    /// Filter by minimum serial.
    #[schema(inline)]
    #[param(inline)]
    pub min_serial: Option<Serial>,
    /// Filter by maximum serial.
    #[schema(inline)]
    #[param(inline)]
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
    #[param(minimum = 1, maximum = 1000)]
    pub limit: Option<u32>,
    /// Number of zones to skip.
    #[schema(example = 0)]
    pub offset: Option<u64>,
}

/// Update a zone, resolving omitted fields from the locked row.
/// `serial` is accepted only at creation and is not an update field.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
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
    #[schema(example = 3600, minimum = 60, maximum = 604_800)]
    pub default_ttl: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = 7200)]
    pub refresh: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = 3600)]
    pub retry: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = 604_800)]
    pub expire: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(schema_with = build_minimum_ttl_schema)]
    pub minimum_ttl: Option<i64>,
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

/// What deleting a zone takes with it. A dry run reports the counts and
/// removes nothing; deleting a zone cannot be undone from the tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DeleteZoneResponse {
    /// Whether this call removed the zone; a dry run answers `false`.
    #[schema(example = true)]
    pub applied: bool,
    #[schema(example = false)]
    pub dry_run: bool,
    pub zone: ZoneResponse,
    /// Records the zone holds, all of which go with it.
    #[schema(example = 1240)]
    pub records_deleted: u64,
    /// Saved versions, so the rollback history goes too.
    #[schema(example = 12)]
    pub versions_deleted: u64,
}

/// A single zone wrapped in a response envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SingleZoneResponse {
    pub zone: ZoneResponse,
}

/// What a zone write left behind. The zone's own fields are the change, so
/// unlike a record write this carries no diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct WriteZoneResponse {
    /// Whether this call wrote; a dry run answers `false`.
    #[schema(example = true)]
    pub applied: bool,
    #[schema(example = false)]
    pub dry_run: bool,
    pub zone: ZoneResponse,
}

/// A zone rendered as BIND master-file text. Only the daemon socket wraps the
/// export this way; the HTTP endpoint serves the text as its body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportZoneFileResponse {
    pub zone_file: String,
}

/// How the serial a secondary serves compares with the one Bindizr serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecondaryStatus {
    InSync,
    Lagging,
    Ahead,
    /// The secondary answered, but serials could not be ordered (unknown or RFC 1982 half-range).
    Reachable,
    Unreachable,
}

impl SecondaryStatus {
    /// Return the canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InSync => "in_sync",
            Self::Lagging => "lagging",
            Self::Ahead => "ahead",
            Self::Reachable => "reachable",
            Self::Unreachable => "unreachable",
        }
    }
}

impl fmt::Display for SecondaryStatus {
    /// Write the status as a person reads it; serde spells the API form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InSync => "in sync",
            Self::Lagging => "lagging",
            Self::Ahead => "ahead",
            Self::Reachable => "reachable",
            Self::Unreachable => "unreachable",
        })
    }
}

/// What one secondary answered when probed for a zone's SOA, classified
/// against the serial Bindizr serves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SecondaryStatusResponse {
    #[schema(example = "10.0.1.10:53")]
    pub address: String,
    pub status: SecondaryStatus,
    #[schema(inline)]
    pub visible_serial: Option<Serial>,
    pub error: Option<String>,
    /// The latest transfer of this zone Bindizr served the address.
    pub last_transfer: Option<TransferResponse>,
}

impl SecondaryStatusResponse {
    /// Return whether the probed secondary serial matches this status's zone serial.
    pub fn is_in_sync(&self) -> bool {
        self.status == SecondaryStatus::InSync
    }

    /// Return whether the secondary probe failed to obtain a serial.
    pub fn is_unreachable(&self) -> bool {
        self.status == SecondaryStatus::Unreachable
    }
}

/// A zone's serial and the sync state of every enabled secondary, probed
/// live via SOA queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ZoneStatusResponse {
    #[schema(example = "example.com")]
    pub zone_name: String,
    #[schema(inline)]
    pub serial: Serial,
    pub secondaries: Vec<SecondaryStatusResponse>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Verify that `ZoneView` has one spelling across `as_str` and serde.
    #[test]
    fn zone_view_spells_itself_once() {
        for value in [ZoneView::Plain, ZoneView::Signed] {
            assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
            assert_eq!(
                serde_json::from_value::<ZoneView>(json!(value.as_str())).unwrap(),
                value
            );
        }
    }

    /// Verify that `NotifySerial` has one spelling across `as_str` and serde.
    #[test]
    fn notify_serial_spells_itself_once() {
        for value in [NotifySerial::Keep, NotifySerial::Bump] {
            assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
            assert_eq!(
                serde_json::from_value::<NotifySerial>(json!(value.as_str())).unwrap(),
                value
            );
        }
    }

    /// Verify that `SecondaryStatus` has one spelling across `as_str` and serde.
    #[test]
    fn secondary_status_spells_itself_once() {
        for value in [
            SecondaryStatus::InSync,
            SecondaryStatus::Lagging,
            SecondaryStatus::Ahead,
            SecondaryStatus::Reachable,
            SecondaryStatus::Unreachable,
        ] {
            assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
            assert_eq!(
                serde_json::from_value::<SecondaryStatus>(json!(value.as_str())).unwrap(),
                value
            );
        }
    }
}
