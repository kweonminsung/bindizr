//! Zone import payloads, for one zone and for several from one server.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{common::ErrorResponse, version::RecordDiffResponse};

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
    /// Create a missing zone from the SOA; otherwise a missing zone is an error.
    /// Requires `zone:create` and the mode's record actions in all zones.
    /// The initial serial accepts the full unsigned 32-bit range (0..=4294967295);
    /// applying record changes advances it once modulo 2^32.
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
    pub summary: ImportZoneSummaryResponse,
    /// The reconcile as a record diff, for previewing the change.
    pub diff: RecordDiffResponse,
    /// Per-record validation errors. When non-empty nothing is applied.
    pub errors: Vec<String>,
}

impl ImportZoneResponse {
    /// Whether the file was refused whole. `applied` cannot answer this: a
    /// clean dry run also leaves it false.
    pub fn was_rejected(&self) -> bool {
        !self.errors.is_empty()
    }
}

/// Import record counts; `updated` counts TTL-only changes and excludes `unchanged`.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, ToSchema)]
pub struct ImportZoneSummaryResponse {
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
            create: false,
        }
    }
}

/// Request body for importing several zones from one server over AXFR:
/// those in `zone_names`, or the members of its catalog zone `from_catalog`
/// (RFC 9432); exactly one of the two.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ImportZonesRequest {
    /// Transfer source (`host[:port]`, port 53 default); it must allow the transfers.
    #[schema(example = "192.0.2.1:53")]
    pub from_server: String,
    /// The zones to import, as the source serves them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = json!(["example.com", "example.net"]))]
    pub zone_names: Option<Vec<String>>,
    /// The source's catalog zone, whose members are the zones to import.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "catalog.example")]
    pub from_catalog: Option<String>,
    /// Reconciliation mode for every zone: `append` (default), `upsert`, or `replace`.
    #[serde(default = "default_import_mode")]
    #[schema(value_type = ImportMode, default = "append", example = "replace")]
    pub mode: String,
    /// When true, parse and validate every zone without applying any change.
    #[serde(default)]
    pub dry_run: bool,
    /// Create a missing zone from its SOA; otherwise it fails. Requires
    /// `zone:create` and the mode's record actions in all zones.
    #[serde(default)]
    pub create: bool,
}

/// How one zone of a bulk import came out.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ImportResult {
    /// The import ran: applied, or previewed on a dry run.
    Ok,
    /// Validation errors; nothing applied, the errors in `import`.
    Rejected,
    /// Never imported: the transfer failed, the zone is missing without
    /// `create`, or the caller may not touch it.
    Failed,
}

impl ImportResult {
    /// Return the canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
        }
    }
}

impl std::fmt::Display for ImportResult {
    /// Write the result as the API spells it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One zone of a bulk import: its result with the import answer or the error.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct ImportZonesItemResponse {
    #[schema(example = "example.com")]
    pub zone_name: String,
    pub result: ImportResult,
    /// The zone's own import answer; null when the import never ran.
    pub import: Option<ImportZoneResponse>,
    /// Why the import never ran; null otherwise.
    pub error: Option<ErrorResponse>,
}

/// How many zones of a bulk import came out each way.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, ToSchema)]
pub struct ImportZonesSummaryResponse {
    #[schema(example = 12)]
    pub zones: u64,
    #[schema(example = 10)]
    pub ok: u64,
    #[schema(example = 1)]
    pub rejected: u64,
    #[schema(example = 1)]
    pub failed: u64,
}

/// Result of a bulk import: one entry per zone, in the order imported.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct ImportZonesResponse {
    #[schema(example = false)]
    pub dry_run: bool,
    pub summary: ImportZonesSummaryResponse,
    pub zones: Vec<ImportZonesItemResponse>,
}

impl ImportZonesResponse {
    /// Whether any zone was rejected or failed; not a success for a script.
    pub fn has_rejected_or_failed(&self) -> bool {
        self.summary.rejected > 0 || self.summary.failed > 0
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

    /// Verify that `ImportResult` has one spelling across `as_str` and serde.
    #[test]
    fn import_result_spells_itself_once() {
        for value in [
            ImportResult::Ok,
            ImportResult::Rejected,
            ImportResult::Failed,
        ] {
            assert_eq!(
                serde_json::to_value(value).unwrap(),
                serde_json::json!(value.as_str())
            );
            assert_eq!(
                serde_json::from_value::<ImportResult>(serde_json::json!(value.as_str())).unwrap(),
                value
            );
        }
    }

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
