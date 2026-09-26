//! Zone version, diff, and rollback payloads.

use bindizr_core::dns::{name::ZoneName, record::SoaMailbox, serial_to_u32};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::record::{RecordValueRequest, build_display_value};
use crate::{
    error::ServiceError,
    model::{
        record::RecordData,
        zone_version::{ChangeSource, ZoneVersion},
    },
};

/// One entry of a zone's serial history, with SOA metadata in API form
/// (`rname` converted back from SOA mailbox form).
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct ZoneVersionResponse {
    #[schema(example = 7)]
    pub serial: u32,
    #[schema(example = "ns1.example.com")]
    pub mname: String,
    #[schema(example = "admin@example.com")]
    pub rname: String,
    #[schema(example = 3600)]
    pub default_ttl: i32,
    #[schema(example = 7200)]
    pub refresh: i32,
    #[schema(example = 3600)]
    pub retry: i32,
    #[schema(example = 604800)]
    pub expire: i32,
    #[schema(example = 3600)]
    pub minimum_ttl: i32,
    /// Which plane asked for this version: `token`, `nsupdate`, `system`
    /// (the DNSSEC scheduler), or `local` (the daemon socket, or
    /// any request while authentication is disabled).
    pub change_source: ChangeSource,
    /// The API token or TSIG key the change was made under, absent where no
    /// credential stood behind it.
    #[schema(example = "admin")]
    pub changed_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl ZoneVersionResponse {
    /// Build a zone-version response from its stored metadata.
    pub(crate) fn from_version(version: &ZoneVersion) -> Result<Self, ServiceError> {
        let rname = SoaMailbox::from_encoded(&version.rname)
            .to_email()
            .map_err(|e| {
                ServiceError::internal(format!("Failed to decode version rname: {}", e))
            })?;
        Ok(ZoneVersionResponse {
            serial: serial_to_u32(version.serial).map_err(ServiceError::internal)?,
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

/// A record reconstructed from the zone's journal, named as the record
/// listing names it; unlike stored records it has no database id.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct VersionRecordResponse {
    #[schema(example = "www.example.com.")]
    pub name: String,
    #[serde(rename = "type")]
    #[schema(example = "A")]
    pub record_type: String,
    pub value: RecordValueRequest,
    #[schema(example = 3600)]
    pub ttl: i32,
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

/// One version plus the reconstructed records at that serial.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct VersionDetailResponse {
    pub version: ZoneVersionResponse,
    pub records: Vec<VersionRecordResponse>,
}

/// One record on one side of a diff. Rendering (zone-file rdata, priority
/// placement) is left to the client; the value is in display form.
#[derive(Clone, Serialize, Deserialize, Debug, ToSchema)]
pub struct RecordDiffValue {
    pub value: RecordValueRequest,
    #[schema(example = 300)]
    pub ttl: i32,
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

/// The records of one name and type that differ, with those present on
/// each side. `from` is empty for `added`, `to` for `removed`.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
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
#[derive(Default, Serialize, Deserialize, Debug, ToSchema)]
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
#[derive(Default, Serialize, Deserialize, Debug, ToSchema)]
pub struct RecordDiff {
    pub entries: Vec<RecordDiffEntry>,
    pub summary: RecordDiffSummary,
}

/// The difference between two of a zone's serials.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct VersionDiffResponse {
    #[schema(example = 41)]
    pub from_serial: u32,
    #[schema(example = 42)]
    pub to_serial: u32,
    pub diff: RecordDiff,
}

/// Counts of what a rollback changes. TTL-only differences count as one
/// delete plus one add.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
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
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct RollbackZoneResponse {
    #[schema(example = true)]
    pub applied: bool,
    #[schema(example = false)]
    pub dry_run: bool,
    #[schema(example = 7)]
    pub target_serial: u32,
    #[schema(example = 13)]
    pub new_serial: u32,
    pub summary: RollbackSummary,
}
