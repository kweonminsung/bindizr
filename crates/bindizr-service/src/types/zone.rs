//! Zone request, patch, filter, and response payloads.

use bindizr_core::{
    dns::{record::SoaMailbox, zonefile::ZoneFileSoa},
    model::written_id,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{error::ServiceError, model::zone::Zone, serial::validate_initial_serial};

/// API representation of a zone.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct GetZoneResponse {
    /// Absent on a dry run, where nothing was written to carry one.
    #[schema(example = 1)]
    pub id: Option<i32>,
    #[schema(example = "example.com")]
    pub name: String,
    #[schema(example = "ns1.example.com")]
    pub mname: String,
    #[schema(example = "admin@example.com")]
    pub rname: String,
    #[schema(example = 3600)]
    pub default_ttl: i32,
    #[schema(example = 42)]
    pub serial: i32,
    #[schema(example = 7200)]
    pub refresh: i32,
    #[schema(example = 3600)]
    pub retry: i32,
    #[schema(example = 604800)]
    pub expire: i32,
    #[schema(example = 3600)]
    pub minimum_ttl: i32,
    /// Whether the DNS plane serves the zone. A disabled one stays editable but
    /// leaves the catalog and answers no transfer, so secondaries drop it.
    #[schema(example = true)]
    pub enabled: bool,
    pub description: Option<String>,
}

impl GetZoneResponse {
    /// Build a zone response from its stored settings.
    pub fn from_zone(zone: &Zone) -> Self {
        GetZoneResponse {
            id: written_id(zone.id),
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
#[derive(Serialize, Deserialize, Debug, ToSchema)]
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
    #[schema(example = 42)]
    pub serial: Option<i32>,
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
    /// Validate and report the change without writing it.
    #[serde(default)]
    #[schema(example = false)]
    pub dry_run: bool,
}

impl CreateZoneRequest {
    /// Build the request a zone file's SOA describes. The serial carries over
    /// so secondaries holding the old primary's serial accept the transfer;
    /// one past bindizr's ceiling starts fresh instead.
    pub(crate) fn from_zone_file_soa(
        zone_name: &str,
        soa: &ZoneFileSoa,
    ) -> Result<Self, ServiceError> {
        let rname = SoaMailbox::from_encoded(soa.rname.trim_end_matches('.'))
            .to_email()
            .map_err(|e| {
                ServiceError::invalid_input(format!("the SOA's RNAME is not an address: {}", e))
            })?;
        Ok(CreateZoneRequest {
            dry_run: false,
            name: zone_name.to_string(),
            mname: soa.mname.clone(),
            rname,
            default_ttl: None,
            // The file's serial only if a zone may start from it, so an
            // unusable one generates a fresh serial instead of failing.
            serial: i32::try_from(soa.serial)
                .ok()
                .and_then(|serial| validate_initial_serial(serial).ok()),
            refresh: Some(soa.refresh),
            retry: Some(soa.retry),
            expire: Some(soa.expire),
            minimum_ttl: Some(soa.minimum_ttl),
            description: None,
        })
    }
}

/// Query filters and pagination for listing zones.
#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GetZonesFilter {
    #[schema(example = "example.com")]
    pub name: Option<String>,
    #[schema(example = 1)]
    pub id: Option<i32>,
    #[schema(example = "ns1.example.com")]
    pub mname: Option<String>,
    #[schema(example = "admin@example.com")]
    pub rname: Option<String>,
    #[schema(example = 3600)]
    pub default_ttl: Option<i32>,
    #[schema(example = 300)]
    pub min_default_ttl: Option<i32>,
    #[schema(example = 86400)]
    pub max_default_ttl: Option<i32>,
    #[schema(example = 42)]
    pub serial: Option<i32>,
    #[schema(example = 1)]
    pub min_serial: Option<i32>,
    #[schema(example = 99)]
    pub max_serial: Option<i32>,
    pub created_after: Option<DateTime<Utc>>,
    pub created_before: Option<DateTime<Utc>>,
    /// `true` keeps the zones signing under a DNSSEC policy, `false` the rest.
    #[schema(example = true)]
    pub signed: Option<bool>,
    /// `true` keeps the zones the DNS plane serves, `false` the disabled ones.
    #[schema(example = true)]
    pub enabled: Option<bool>,
    #[schema(example = "example")]
    pub search: Option<String>,
    /// `name` (the default), `serial`, `default_ttl`, or `created_at`.
    #[schema(example = "name")]
    pub sort: Option<String>,
    /// `asc` (the default) or `desc`.
    #[schema(example = "asc")]
    pub order: Option<String>,
    /// Defaults to 50 when omitted; 1000 is the largest page accepted.
    #[schema(example = 50)]
    pub limit: Option<u32>,
    #[schema(example = 0)]
    pub offset: Option<u64>,
}

/// Request body for updating a zone; an omitted field keeps the current
/// value, merged inside the update transaction. `serial` is carried only to
/// be rejected: it is fixed at creation.
#[derive(Serialize, Deserialize, Debug, Default, ToSchema)]
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
    pub serial: Option<i32>,
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
pub fn build_notify_message(zone_name: Option<&str>, bump_serial: bool) -> String {
    let scope = match zone_name {
        Some(zone_name) => format!("zone: {}", zone_name),
        None => "all zones".to_string(),
    };
    let suffix = if bump_serial { " (serial bumped)" } else { "" };
    format!("NOTIFY sent successfully for {}{}", scope, suffix)
}

/// What deleting a zone takes with it. A dry run reports the counts and
/// removes nothing; deleting a zone cannot be undone from the tool.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct DeleteZoneResponse {
    /// Whether this call removed the zone; a dry run answers `false`.
    #[schema(example = true)]
    pub applied: bool,
    #[schema(example = false)]
    pub dry_run: bool,
    pub zone: GetZoneResponse,
    /// Records the zone holds, all of which go with it.
    #[schema(example = 1240)]
    pub records: u64,
    /// Saved versions, so the rollback history goes too.
    #[schema(example = 12)]
    pub versions: u64,
}

/// A single zone wrapped in a response envelope. A dry run answers with the
/// zone as it would stand and `applied: false`.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct ZoneResponse {
    pub zone: GetZoneResponse,
}

/// What a zone write left behind. The zone's own fields are the change, so
/// unlike a record write this carries no diff.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
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
#[derive(Serialize, Deserialize, Debug)]
pub struct ExportZoneFileResponse {
    pub zone_file: String,
}

/// What one secondary answered when probed for a zone's SOA, classified
/// against the serial Bindizr serves.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct SecondaryStatusResponse {
    #[schema(example = "10.0.1.10:53")]
    pub address: String,
    /// `in_sync` | `lagging` | `ahead` | `unreachable`, or `reachable` when
    /// the secondary answered but Bindizr's own serial was not known.
    #[schema(example = "in_sync")]
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = 42)]
    pub visible_serial: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SecondaryStatusResponse {
    /// Classify a probed SOA serial against the serial Bindizr serves; a
    /// probe error reads as `unreachable`, an answer with nothing to compare
    /// it to as `reachable`.
    pub fn from_probe(
        address: String,
        expected_serial: Option<u32>,
        result: Result<u32, String>,
    ) -> Self {
        match result {
            Ok(visible) => {
                let status = match expected_serial {
                    Some(expected) => match visible.cmp(&expected) {
                        std::cmp::Ordering::Equal => "in_sync",
                        std::cmp::Ordering::Less => "lagging",
                        std::cmp::Ordering::Greater => "ahead",
                    },
                    None => "reachable",
                };
                SecondaryStatusResponse {
                    address,
                    status: status.to_string(),
                    visible_serial: Some(visible),
                    error: None,
                }
            }
            Err(error) => SecondaryStatusResponse {
                address,
                status: "unreachable".to_string(),
                visible_serial: None,
                error: Some(error),
            },
        }
    }

    /// Whether the probed secondary serial matches this status's zone serial.
    pub fn is_in_sync(&self) -> bool {
        self.status == "in_sync"
    }

    /// Check whether the secondary probe failed to obtain a serial.
    pub fn is_unreachable(&self) -> bool {
        self.status == "unreachable"
    }
}

/// A zone's serial and the sync state of every enabled secondary, probed
/// live via SOA queries.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct ZoneStatusResponse {
    #[schema(example = "example.com")]
    pub zone: String,
    #[schema(example = 42)]
    pub serial: u32,
    pub secondaries: Vec<SecondaryStatusResponse>,
}

impl ZoneStatusResponse {
    /// Classify each secondary's probed SOA serial against the zone's.
    pub(crate) fn from_probes(
        zone: &str,
        serial: u32,
        probes: impl IntoIterator<Item = (String, Result<u32, String>)>,
    ) -> Self {
        let secondaries = probes
            .into_iter()
            .map(|(address, result)| {
                SecondaryStatusResponse::from_probe(address, Some(serial), result)
            })
            .collect();

        ZoneStatusResponse {
            zone: zone.to_string(),
            serial,
            secondaries,
        }
    }
}
