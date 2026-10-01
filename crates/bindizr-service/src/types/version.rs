//! Zone version, diff, and rollback payloads.

use bindizr_core::dns::{Serial, SoaInterval, Ttl, name::ZoneName, record::SoaMailbox};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::record::{RecordValueRequest, build_display_value};
use crate::{
    error::ServiceError,
    model::{
        record::RecordData,
        zone_version::{ChangeActor, ChangeSource, ZoneVersion},
    },
};

/// One entry of a zone's serial history, with SOA metadata in API form
/// (`rname` converted back from SOA mailbox form).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct ZoneVersionResponse {
    #[schema(example = 7, value_type = u32)]
    pub serial: Serial,
    #[schema(example = "ns1.example.com")]
    pub mname: String,
    #[schema(example = "admin@example.com")]
    pub rname: String,
    #[schema(example = 3600, value_type = i32)]
    pub default_ttl: Ttl,
    #[schema(example = 7200, value_type = i32)]
    pub refresh: SoaInterval,
    #[schema(example = 3600, value_type = i32)]
    pub retry: SoaInterval,
    #[schema(example = 604800, value_type = i32)]
    pub expire: SoaInterval,
    #[schema(example = 3600, value_type = i32)]
    pub minimum_ttl: Ttl,
    /// The request path (`api`, `socket`, `nsupdate`) or background process (`system`).
    pub change_source: ChangeSource,
    /// Token or TSIG key kind and name. Null for socket commands, unauthenticated
    /// API requests, unsigned updates, and background work.
    pub changed_by: Option<ChangeActor>,
    pub created_at: DateTime<Utc>,
}

impl TryFrom<&ZoneVersion> for ZoneVersionResponse {
    type Error = ServiceError;

    /// Build a zone-version response from its stored metadata; a stored
    /// mailbox or serial that does not decode is a server fault.
    fn try_from(version: &ZoneVersion) -> Result<Self, ServiceError> {
        let rname = SoaMailbox::from_encoded(&version.rname)
            .to_email()
            .map_err(|e| {
                ServiceError::internal(format!("Failed to decode version rname: {}", e))
            })?;
        Ok(ZoneVersionResponse {
            serial: version.serial,
            mname: version.mname.clone(),
            rname,
            default_ttl: version.default_ttl,
            refresh: version.refresh,
            retry: version.retry,
            expire: version.expire,
            minimum_ttl: version.minimum_ttl,
            change_source: version.change_source,
            changed_by: version.changed_by.clone(),
            created_at: version.created_at,
        })
    }
}

/// A record rewound from the zone's journal, named as the record
/// listing names it; unlike stored records it has no database id.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct VersionRecordResponse {
    #[schema(example = "www.example.com.")]
    pub name: String,
    #[serde(rename = "type")]
    #[schema(example = "A")]
    pub record_type: String,
    pub value: RecordValueRequest,
    #[schema(example = 3600, value_type = i32)]
    pub ttl: Ttl,
    #[schema(example = 10)]
    pub priority: Option<i32>,
}

impl VersionRecordResponse {
    /// Build a version-record response from a record's data, its owner
    /// rendered absolute within `zone_name`.
    pub(crate) fn from_record_and_zone_name(record: &RecordData, zone_name: &ZoneName) -> Self {
        VersionRecordResponse {
            name: record.name.to_fqdn(zone_name),
            record_type: record.record_type.to_string(),
            // Decode TXT out of its stored form, as the record endpoints do.
            value: build_display_value(&record.value, &record.record_type),
            ttl: record.ttl,
            priority: record.priority,
        }
    }
}

/// One version plus the records rewound to that serial.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct VersionDetailResponse {
    pub version: ZoneVersionResponse,
    pub records: Vec<VersionRecordResponse>,
}

/// One record on one side of a diff. Rendering (zone-file rdata, priority
/// placement) is left to the client; the value is in display form.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct RecordDiffValue {
    pub value: RecordValueRequest,
    #[schema(example = 300, value_type = i32)]
    pub ttl: Ttl,
    #[schema(example = 10)]
    pub priority: Option<i32>,
}

/// Which way the records of one name and type differ between two serials.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum RecordChange {
    Added,
    Removed,
    Changed,
}

impl std::fmt::Display for RecordChange {
    /// Write the change as its diff mark.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            RecordChange::Added => "+",
            RecordChange::Removed => "-",
            RecordChange::Changed => "~",
        })
    }
}

/// The records of one name and type that differ, with those present on
/// each side. `from` is empty for `added`, `to` for `removed`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct RecordDiffEntry {
    pub change: RecordChange,
    #[schema(example = "www.example.com.")]
    pub name: String,
    #[serde(rename = "type")]
    #[schema(example = "A")]
    pub record_type: String,
    pub from: Vec<RecordDiffValue>,
    pub to: Vec<RecordDiffValue>,
}

/// How many name-and-type groups of records were added, removed, and changed.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default, ToSchema)]
pub struct RecordDiffSummary {
    #[schema(example = 1)]
    pub added: u64,
    #[schema(example = 1)]
    pub removed: u64,
    #[schema(example = 1)]
    pub changed: u64,
}

/// Record differences grouped by name and type. Version comparisons always
/// populate this; mutation responses populate it only for dry-run previews.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default, ToSchema)]
pub struct RecordDiff {
    pub entries: Vec<RecordDiffEntry>,
    pub summary: RecordDiffSummary,
}

/// The difference between two of a zone's serials.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct VersionDiffResponse {
    #[schema(example = 41, value_type = u32)]
    pub from_serial: Serial,
    #[schema(example = 42, value_type = u32)]
    pub to_serial: Serial,
    pub diff: RecordDiff,
}

/// Counts of what a rollback changes. TTL-only differences count as one
/// delete plus one add.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct RollbackSummary {
    #[schema(example = 2)]
    pub added: u64,
    #[schema(example = 3)]
    pub deleted: u64,
    #[schema(example = 5)]
    pub unchanged: u64,
    #[schema(example = true)]
    pub soa_changed: bool,
}

/// Result of a zone rollback. The zone's state returns to `target_serial`
/// while its serial advances to `new_serial` (serials never go backward).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct RollbackZoneResponse {
    #[schema(example = true)]
    pub applied: bool,
    #[schema(example = false)]
    pub dry_run: bool,
    #[schema(example = 7, value_type = u32)]
    pub target_serial: Serial,
    #[schema(example = 13, value_type = u32)]
    pub new_serial: Serial,
    pub summary: RollbackSummary,
}
