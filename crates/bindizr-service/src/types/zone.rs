//! Zone request, patch, filter, and response payloads.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::record::GetRecordResponse;
use crate::model::zone::Zone;

/// API representation of a zone.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct GetZoneResponse {
    #[schema(example = 1)]
    pub id: i32,
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
}

impl GetZoneResponse {
    pub fn from_zone(zone: &Zone) -> Self {
        GetZoneResponse {
            id: zone.id,
            name: zone.name.to_string(),
            mname: zone.mname.clone(),
            rname: zone.rname.clone(),
            default_ttl: zone.default_ttl,
            serial: zone.serial,
            refresh: zone.refresh,
            retry: zone.retry,
            expire: zone.expire,
            minimum_ttl: zone.minimum_ttl,
        }
    }
}

/// Request body for creating or updating a zone.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct CreateZoneRequest {
    #[schema(example = "example.com")]
    pub name: String,
    #[schema(example = "ns1.example.com")]
    pub mname: String,
    #[schema(example = "admin@example.com")]
    pub rname: String,
    #[schema(example = 3600)]
    pub default_ttl: i32,
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
}

/// Query filters and pagination for listing zones.
#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
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
    #[serde(alias = "q")]
    #[schema(example = "example")]
    pub search: Option<String>,
    #[schema(example = 50)]
    pub limit: Option<u32>,
    #[schema(example = 0)]
    pub offset: Option<u64>,
}

/// A partial zone update; an omitted field keeps the current value, merged
/// inside the update transaction. `serial` is carried only to be rejected.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct UpdateZonePatch {
    pub new_name: Option<String>,
    pub mname: Option<String>,
    pub rname: Option<String>,
    pub default_ttl: Option<i32>,
    pub refresh: Option<i32>,
    pub retry: Option<i32>,
    pub expire: Option<i32>,
    pub minimum_ttl: Option<i32>,
    pub serial: Option<i32>,
}

/// Request body for triggering a NOTIFY, optionally scoped to one zone.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct NotifyZoneRequest {
    #[schema(example = "example.com")]
    pub zone_name: Option<String>,
    /// Bump the serial first, so secondaries transfer even when nothing
    /// changed.
    #[serde(default)]
    #[schema(example = true)]
    pub bump_serial: bool,
}

impl NotifyZoneRequest {
    /// The success message every front end serves for this request.
    pub fn success_message(&self) -> String {
        let scope = match &self.zone_name {
            Some(zone_name) => format!("zone: {}", zone_name),
            None => "all zones".to_string(),
        };
        let suffix = if self.bump_serial {
            " (serial bumped)"
        } else {
            ""
        };
        format!("NOTIFY sent successfully for {}{}", scope, suffix)
    }
}

/// A zone together with all of its records.
#[derive(Serialize, Debug, ToSchema)]
pub struct ZoneDetailResponse {
    pub zone: GetZoneResponse,
    pub records: Vec<GetRecordResponse>,
}

/// A single zone wrapped in a response envelope.
#[derive(Serialize, Debug, ToSchema)]
pub struct ZoneResponse {
    pub zone: GetZoneResponse,
}

/// A zone rendered as BIND master-file text. Only the daemon socket wraps the
/// export this way; the HTTP endpoint serves the text as its body.
#[derive(Serialize, Deserialize, Debug)]
pub struct ExportZoneFileResponse {
    pub zone_file: String,
}

/// Sync state of one configured secondary for a zone.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct SecondaryStatusResponse {
    #[schema(example = "10.0.1.10:53")]
    pub address: String,
    /// `in_sync` | `lagging` | `ahead` | `unreachable`
    #[schema(example = "in_sync")]
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = 42)]
    pub visible_serial: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SecondaryStatusResponse {
    /// The wire status strings are minted only in
    /// [`ZoneStatusResponse::from_probes`]; consumers test them through these
    /// predicates so a renamed state cannot silently stop matching.
    pub fn is_in_sync(&self) -> bool {
        self.status == "in_sync"
    }

    pub fn is_unreachable(&self) -> bool {
        self.status == "unreachable"
    }
}

/// A zone's serial and the sync state of every configured secondary, probed
/// live via SOA queries.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct ZoneStatusResponse {
    #[schema(example = "example.com")]
    pub zone: String,
    #[schema(example = 42)]
    pub serial: i32,
    pub secondaries: Vec<SecondaryStatusResponse>,
}

impl ZoneStatusResponse {
    /// Classify each secondary's probed SOA serial against the zone's serial;
    /// a probe error reads as `unreachable`.
    pub fn from_probes(
        zone: &Zone,
        probes: impl IntoIterator<Item = (String, Result<u32, String>)>,
    ) -> Self {
        let secondaries = probes
            .into_iter()
            .map(|(address, result)| match result {
                Ok(visible) => {
                    let visible = i64::from(visible);
                    let status = match visible.cmp(&i64::from(zone.serial)) {
                        std::cmp::Ordering::Equal => "in_sync",
                        std::cmp::Ordering::Less => "lagging",
                        std::cmp::Ordering::Greater => "ahead",
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
            })
            .collect();

        ZoneStatusResponse {
            zone: zone.name.to_string(),
            serial: zone.serial,
            secondaries,
        }
    }
}
