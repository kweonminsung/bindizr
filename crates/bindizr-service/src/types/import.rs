//! Zone import request, mode, and summary payloads.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::version::RecordDiff;

/// How parsed records are reconciled with the records already in the zone.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ImportMode {
    /// Add parsed records; records already present are left untouched.
    #[default]
    Append,
    /// Replace the records of every name and type that appears in the file
    /// with the parsed records, leaving other names and types untouched.
    Upsert,
    /// Replace all non-protected records in the zone with the parsed records.
    Replace,
}

/// Request body for importing records into a zone: BIND zone file text in
/// `content`, or a transfer from `from_server`; exactly one of the two.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ImportZoneRequest {
    /// Raw BIND zone file text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "www IN A 192.0.2.1\nmail IN A 192.0.2.2\n")]
    pub content: Option<String>,
    /// Transfer source (`host[:port]`, port 53 default) to pull the zone
    /// from over AXFR; its SOA seeds a missing zone when `create` is true.
    /// SOA and DNSSEC-derived records are not imported as ordinary records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "192.0.2.1:53")]
    pub from_server: Option<String>,
    /// Reconciliation mode: `append` (default), `upsert`, or `replace`.
    #[serde(default = "default_import_mode")]
    #[schema(value_type = ImportMode, default = "append", example = "append")]
    pub mode: String,
    /// When true, parse and validate without applying any change.
    #[serde(default)]
    pub dry_run: bool,
    /// Pass over records bindizr has no type for instead of failing the whole
    /// file; they are counted as skipped and listed in `skipped_records`.
    #[serde(default)]
    pub skip_unsupported: bool,
    /// Create the zone from the file's SOA when it does not exist yet, which
    /// needs `zone:create` and the mode's record actions in all zones. Its
    /// initial serial must be 1..=2137483647; an unsupported serial rejects
    /// both a dry run and an apply without creating the zone. Applying record
    /// changes advances the serial once. Without this a missing zone is an
    /// error, so a typo creates nothing.
    #[serde(default)]
    pub create: bool,
}

/// Result of a zone import, including a summary and any validation errors.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct ImportZoneResponse {
    #[schema(example = true)]
    pub applied: bool,
    #[schema(example = false)]
    pub dry_run: bool,
    pub summary: ImportSummary,
    /// The reconcile as a record diff, for previewing the change.
    pub diff: RecordDiff,
    /// Per-record validation errors. When non-empty nothing is applied.
    pub errors: Vec<String>,
    /// Records passed over under `skip_unsupported`.
    #[serde(default)]
    pub skipped_records: Vec<String>,
}

impl ImportZoneResponse {
    /// Whether the file was refused whole. `applied` cannot answer this: a
    /// clean dry run also leaves it false.
    pub fn was_rejected(&self) -> bool {
        !self.errors.is_empty()
    }
}

/// Counts of records parsed, added, deleted, updated, unchanged, and skipped
/// during import. `updated` is a TTL-only reconcile and is never also counted
/// as `unchanged`.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, ToSchema)]
pub struct ImportSummary {
    #[schema(example = 12)]
    pub parsed: u64,
    #[schema(example = 8)]
    pub added: u64,
    #[schema(example = 2)]
    pub deleted: u64,
    #[schema(example = 1)]
    pub updated: u64,
    #[schema(example = 2)]
    pub unchanged: u64,
    #[schema(example = 0)]
    pub skipped: u64,
}

impl ImportMode {
    /// Return the canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Append => "append",
            Self::Upsert => "upsert",
            Self::Replace => "replace",
        }
    }
}

impl serde::Serialize for ImportMode {
    /// Serialize through the canonical spelling used by the wire contract.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Supply the wire default when an import request omits its mode.
fn default_import_mode() -> String {
    ImportMode::Append.as_str().to_owned()
}

impl Default for ImportZoneRequest {
    /// Default to an append request with all optional actions disabled.
    fn default() -> Self {
        Self {
            content: None,
            from_server: None,
            mode: default_import_mode(),
            dry_run: false,
            skip_unsupported: false,
            create: false,
        }
    }
}

/// An import mode outside the supported reconciliation strategies.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid import mode '{0}': expected append, upsert, or replace")]
pub struct ParseImportModeError(String);

impl std::str::FromStr for ImportMode {
    type Err = ParseImportModeError;

    /// Validate the raw mode supplied in an import request.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "append" => Ok(Self::Append),
            "upsert" => Ok(Self::Upsert),
            "replace" => Ok(Self::Replace),
            _ => Err(ParseImportModeError(value.to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the canonical spelling and round-trip of every ImportMode variant.
    #[test]
    fn import_mode_spells_itself_once() {
        for (value, expected) in [
            (ImportMode::Append, "append"),
            (ImportMode::Upsert, "upsert"),
            (ImportMode::Replace, "replace"),
        ] {
            assert_eq!(value.as_str(), expected);
            assert_eq!(
                serde_json::to_value(value).unwrap(),
                serde_json::json!(expected)
            );
            assert_eq!(
                serde_json::from_value::<ImportMode>(serde_json::json!(expected)).unwrap(),
                value
            );
        }
    }
}
