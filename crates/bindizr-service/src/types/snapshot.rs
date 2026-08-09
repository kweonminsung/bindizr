//! Zone snapshot, diff, and rollback payloads.

use bindizr_core::dns::record::SoaMailbox;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::record::RecordValueRequest;
use crate::{error::ServiceError, model::zone_snapshot::ZoneSnapshot};

/// One entry of a zone's serial history, with SOA metadata in API form
/// (`admin_email` converted back from SOA mailbox form).
#[derive(Serialize, Debug, ToSchema)]
pub struct ZoneSnapshotResponse {
    #[schema(example = 7)]
    pub serial: i32,
    #[schema(example = "ns1.example.com")]
    pub primary_ns: String,
    #[schema(example = "admin@example.com")]
    pub admin_email: String,
    #[schema(example = 3600)]
    pub ttl: i32,
    #[schema(example = 7200)]
    pub refresh: i32,
    #[schema(example = 3600)]
    pub retry: i32,
    #[schema(example = 604800)]
    pub expire: i32,
    #[schema(example = 3600)]
    pub minimum_ttl: i32,
    pub created_at: DateTime<Utc>,
}

impl ZoneSnapshotResponse {
    pub fn from_snapshot(snapshot: &ZoneSnapshot) -> Result<Self, ServiceError> {
        let admin_email = SoaMailbox::from_encoded(&snapshot.admin_email)
            .to_email()
            .map_err(|e| {
                ServiceError::internal(format!("Failed to decode snapshot admin email: {}", e))
            })?;
        Ok(ZoneSnapshotResponse {
            serial: snapshot.serial,
            primary_ns: snapshot.primary_ns.clone(),
            admin_email,
            ttl: snapshot.ttl,
            refresh: snapshot.refresh,
            retry: snapshot.retry,
            expire: snapshot.expire,
            minimum_ttl: snapshot.minimum_ttl,
            created_at: snapshot.created_at,
        })
    }
}

/// A record reconstructed from the zone's change history; unlike stored
/// records it has no database id.
#[derive(Serialize, Debug, ToSchema)]
pub struct SnapshotRecordResponse {
    #[schema(example = "www")]
    pub name: String,
    #[schema(example = "A")]
    pub record_type: String,
    pub value: RecordValueRequest,
    #[schema(example = 3600)]
    pub ttl: i32,
    #[schema(example = 10)]
    pub priority: Option<i32>,
}

/// One snapshot plus the reconstructed record set at that serial.
#[derive(Serialize, Debug, ToSchema)]
pub struct SnapshotDetailResponse {
    pub snapshot: ZoneSnapshotResponse,
    pub records: Vec<SnapshotRecordResponse>,
}

/// One record on one side of a diff. Rendering (zone-file rdata, priority
/// placement) is left to the client; the value is in display form.
#[derive(Clone, Serialize, Debug, ToSchema)]
pub struct RecordDiffValue {
    pub value: RecordValueRequest,
    #[schema(example = 300)]
    pub ttl: i32,
    #[schema(example = 10)]
    pub priority: Option<i32>,
}

/// One RRset (owner name + type) whose records differ, with the records present
/// on each side. `from` is empty for `added`, `to` for `removed`.
#[derive(Serialize, Debug, ToSchema)]
pub struct RecordDiffEntry {
    /// `added`, `removed`, or `changed`.
    #[schema(example = "changed")]
    pub change: String,
    #[schema(example = "www.example.com.")]
    pub name: String,
    #[schema(example = "A")]
    pub record_type: String,
    pub from: Vec<RecordDiffValue>,
    pub to: Vec<RecordDiffValue>,
}

/// How many RRsets were added, removed, and changed.
#[derive(Default, Serialize, Debug, ToSchema)]
pub struct RecordDiffSummary {
    #[schema(example = 1)]
    pub added: usize,
    #[schema(example = 1)]
    pub removed: usize,
    #[schema(example = 1)]
    pub changed: usize,
}

/// A record-level difference between two record sets, RRset by RRset. Empty on
/// a real apply, which does not need it; populated only for a dry-run preview.
#[derive(Default, Serialize, Debug, ToSchema)]
pub struct RecordDiff {
    pub entries: Vec<RecordDiffEntry>,
    pub summary: RecordDiffSummary,
}

/// The difference between two of a zone's serials.
#[derive(Serialize, Debug, ToSchema)]
pub struct SnapshotDiffResponse {
    #[schema(example = 41)]
    pub from_serial: i32,
    #[schema(example = 42)]
    pub to_serial: i32,
    pub diff: RecordDiff,
}

/// Request body for rolling a zone back to a snapshot serial.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct RollbackZoneRequest {
    #[schema(example = 7)]
    pub serial: i32,
    /// When true, compute and report the rollback without applying any change.
    #[serde(default, alias = "dryRun")]
    pub dry_run: bool,
}

/// Counts of what a rollback changes. TTL-only differences count as one
/// delete plus one add.
#[derive(Serialize, Debug, ToSchema)]
pub struct RollbackSummary {
    #[schema(example = 2)]
    pub records_added: usize,
    #[schema(example = 3)]
    pub records_deleted: usize,
    #[schema(example = 5)]
    pub records_unchanged: usize,
    #[schema(example = true)]
    pub soa_changed: bool,
}

/// Result of a zone rollback. The zone's state returns to `target_serial`
/// while its serial advances to `new_serial` (serials never go backward).
#[derive(Serialize, Debug, ToSchema)]
pub struct RollbackZoneResponse {
    #[schema(example = true)]
    pub applied: bool,
    #[schema(example = false)]
    pub dry_run: bool,
    #[schema(example = 7)]
    pub target_serial: i32,
    #[schema(example = 13)]
    pub new_serial: i32,
    pub summary: RollbackSummary,
}
