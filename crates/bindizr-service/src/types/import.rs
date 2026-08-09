//! Zone-file import request, mode, and summary payloads.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::snapshot::RecordDiff;

/// How parsed records are reconciled with the records already in the zone.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ImportMode {
    /// Add parsed records; records already present are left untouched.
    #[default]
    Append,
    /// Replace every RRset (name + type) that appears in the file with the
    /// parsed records, leaving other RRsets untouched.
    Upsert,
    /// Replace all non-protected records in the zone with the parsed records.
    Replace,
}

/// Request body for importing a BIND zone file into a zone.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct ImportZoneFileRequest {
    /// Raw BIND zone file text.
    #[schema(example = "www IN A 192.0.2.1\nmail IN A 192.0.2.2\n")]
    pub content: String,
    #[serde(default)]
    pub mode: ImportMode,
    /// When true, parse and validate without applying any change.
    #[serde(default, alias = "dryRun")]
    pub dry_run: bool,
}

/// Result of a zone-file import, including a summary and any validation errors.
#[derive(Serialize, Debug, ToSchema)]
pub struct ImportZoneFileResponse {
    #[schema(example = true)]
    pub applied: bool,
    #[schema(example = false)]
    pub dry_run: bool,
    pub summary: ImportSummary,
    /// The reconcile as a record diff, for previewing the change.
    pub diff: RecordDiff,
    /// Per-record validation errors. When non-empty nothing is applied.
    pub errors: Vec<String>,
}

/// Counts of records parsed, added, deleted, updated, unchanged, and skipped
/// during import. `updated` is a TTL-only reconcile and is never also counted
/// as `unchanged`.
#[derive(Serialize, Debug, ToSchema)]
pub struct ImportSummary {
    #[schema(example = 12)]
    pub parsed: usize,
    #[schema(example = 8)]
    pub added: usize,
    #[schema(example = 2)]
    pub deleted: usize,
    #[schema(example = 1)]
    pub updated: usize,
    #[schema(example = 2)]
    pub unchanged: usize,
    #[schema(example = 0)]
    pub skipped: usize,
}
