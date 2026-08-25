//! Table rows for CLI output, each built from the typed daemon response so
//! the column set is all this module decides.

use bindizr_service::types::{
    GetRecordResponse, GetZoneResponse, ImportSummary, RecordValueRequest, RollbackZoneResponse,
    SecondaryStatusResponse, VersionRecordResponse, ZoneStatusResponse, ZoneVersionResponse,
};
use tabled::Tabled;

// Display Option<i32> in tables, using "-" for None.
fn display_option_i32(opt: &Option<i32>) -> String {
    match opt {
        Some(val) => val.to_string(),
        None => "-".to_string(),
    }
}

/// A record value as one table cell; TXT segments concatenate into the string
/// they encode.
fn value_text(value: &RecordValueRequest) -> String {
    match value {
        RecordValueRequest::String(value) => value.clone(),
        RecordValueRequest::Segments(segments) => segments.concat(),
    }
}

/// Table row for zone display.
#[derive(Debug, Tabled)]
pub(crate) struct ZoneRow {
    #[tabled(rename = "ID")]
    pub(crate) id: i32,
    #[tabled(rename = "NAME")]
    pub(crate) name: String,
    #[tabled(rename = "MNAME")]
    pub(crate) mname: String,
    #[tabled(rename = "RNAME")]
    pub(crate) rname: String,
    #[tabled(rename = "DEFAULT-TTL")]
    pub(crate) default_ttl: i32,
    #[tabled(rename = "SERIAL")]
    pub(crate) serial: i32,
}

impl From<&GetZoneResponse> for ZoneRow {
    fn from(zone: &GetZoneResponse) -> Self {
        ZoneRow {
            id: zone.id,
            name: zone.name.clone(),
            mname: zone.mname.clone(),
            rname: zone.rname.clone(),
            default_ttl: zone.default_ttl,
            serial: zone.serial,
        }
    }
}

/// Table row for record display.
#[derive(Debug, Tabled)]
pub(crate) struct RecordRow {
    #[tabled(rename = "ID", display = "display_option_i32")]
    pub(crate) id: Option<i32>,
    #[tabled(rename = "NAME")]
    pub(crate) name: String,
    #[tabled(rename = "TYPE")]
    pub(crate) record_type: String,
    #[tabled(rename = "VALUE")]
    pub(crate) value: String,
    #[tabled(rename = "TTL")]
    pub(crate) ttl: i32,
    #[tabled(rename = "PRIORITY", display = "display_option_i32")]
    pub(crate) priority: Option<i32>,
    #[tabled(rename = "ZONE")]
    pub(crate) zone_name: String,
}

impl From<&GetRecordResponse> for RecordRow {
    fn from(record: &GetRecordResponse) -> Self {
        RecordRow {
            id: record.id,
            name: record.name.clone(),
            record_type: record.record_type.clone(),
            value: value_text(&record.value),
            ttl: record.ttl,
            priority: record.priority,
            zone_name: record.zone_name.clone().unwrap_or_default(),
        }
    }
}

/// Table row for zone version display.
#[derive(Debug, Tabled)]
pub(crate) struct VersionRow {
    #[tabled(rename = "SERIAL")]
    pub(crate) serial: i32,
    #[tabled(rename = "MNAME")]
    pub(crate) mname: String,
    #[tabled(rename = "RNAME")]
    pub(crate) rname: String,
    #[tabled(rename = "DEFAULT-TTL")]
    pub(crate) default_ttl: i32,
    #[tabled(rename = "CREATED-AT")]
    pub(crate) created_at: String,
}

impl From<&ZoneVersionResponse> for VersionRow {
    fn from(version: &ZoneVersionResponse) -> Self {
        VersionRow {
            serial: version.serial,
            mname: version.mname.clone(),
            rname: version.rname.clone(),
            default_ttl: version.default_ttl,
            created_at: version.created_at.to_rfc3339(),
        }
    }
}

/// Table row for records reconstructed at a version serial (no database id).
#[derive(Debug, Tabled)]
pub(crate) struct VersionRecordRow {
    #[tabled(rename = "NAME")]
    pub(crate) name: String,
    #[tabled(rename = "TYPE")]
    pub(crate) record_type: String,
    #[tabled(rename = "VALUE")]
    pub(crate) value: String,
    #[tabled(rename = "TTL")]
    pub(crate) ttl: i32,
    #[tabled(rename = "PRIORITY", display = "display_option_i32")]
    pub(crate) priority: Option<i32>,
}

impl From<&VersionRecordResponse> for VersionRecordRow {
    fn from(record: &VersionRecordResponse) -> Self {
        VersionRecordRow {
            name: record.name.clone(),
            record_type: record.record_type.clone(),
            value: value_text(&record.value),
            ttl: record.ttl,
            priority: record.priority,
        }
    }
}

/// Table row for rollback result summaries.
#[derive(Debug, Tabled)]
pub(crate) struct RollbackSummaryRow {
    #[tabled(rename = "TARGET-SERIAL")]
    pub(crate) target_serial: i32,
    #[tabled(rename = "NEW-SERIAL")]
    pub(crate) new_serial: i32,
    #[tabled(rename = "APPLIED")]
    pub(crate) applied: bool,
    #[tabled(rename = "ADDED")]
    pub(crate) records_added: usize,
    #[tabled(rename = "DELETED")]
    pub(crate) records_deleted: usize,
    #[tabled(rename = "UNCHANGED")]
    pub(crate) records_unchanged: usize,
    #[tabled(rename = "SOA-CHANGED")]
    pub(crate) soa_changed: bool,
}

impl From<&RollbackZoneResponse> for RollbackSummaryRow {
    fn from(response: &RollbackZoneResponse) -> Self {
        RollbackSummaryRow {
            target_serial: response.target_serial,
            new_serial: response.new_serial,
            applied: response.applied,
            records_added: response.summary.records_added,
            records_deleted: response.summary.records_deleted,
            records_unchanged: response.summary.records_unchanged,
            soa_changed: response.summary.soa_changed,
        }
    }
}

/// Table row for per-secondary zone sync status.
#[derive(Debug, Tabled)]
pub(crate) struct SecondaryStatusRow {
    #[tabled(rename = "ADDRESS")]
    pub(crate) address: String,
    #[tabled(rename = "STATUS")]
    pub(crate) status: String,
    #[tabled(rename = "VISIBLE-SERIAL")]
    pub(crate) visible_serial: String,
    #[tabled(rename = "LAG")]
    pub(crate) lag: String,
}

impl SecondaryStatusRow {
    /// One row per secondary, with the lag behind the zone serial that its
    /// `status` was classified against.
    pub(crate) fn rows_from_status(status: &ZoneStatusResponse) -> Vec<Self> {
        status
            .secondaries
            .iter()
            .map(|secondary| Self::from_secondary(secondary, status.serial))
            .collect()
    }

    fn from_secondary(secondary: &SecondaryStatusResponse, zone_serial: i32) -> Self {
        let detail = match (secondary.status.as_str(), secondary.error.as_deref()) {
            ("unreachable", Some(error)) => format!("unreachable ({})", error),
            _ => secondary.status.clone(),
        };
        SecondaryStatusRow {
            address: secondary.address.clone(),
            status: detail,
            visible_serial: secondary
                .visible_serial
                .map_or_else(|| "-".to_string(), |serial| serial.to_string()),
            lag: secondary.visible_serial.map_or_else(
                || "-".to_string(),
                |serial| (i64::from(zone_serial) - serial).to_string(),
            ),
        }
    }
}

/// Table row for zone-file import summaries.
#[derive(Debug, Tabled)]
pub(crate) struct ImportSummaryRow {
    #[tabled(rename = "PARSED")]
    pub(crate) parsed: usize,
    #[tabled(rename = "ADDED")]
    pub(crate) added: usize,
    #[tabled(rename = "DELETED")]
    pub(crate) deleted: usize,
    #[tabled(rename = "UPDATED")]
    pub(crate) updated: usize,
    #[tabled(rename = "UNCHANGED")]
    pub(crate) unchanged: usize,
    #[tabled(rename = "SKIPPED")]
    pub(crate) skipped: usize,
}

impl From<&ImportSummary> for ImportSummaryRow {
    fn from(summary: &ImportSummary) -> Self {
        ImportSummaryRow {
            parsed: summary.parsed,
            added: summary.added,
            deleted: summary.deleted,
            updated: summary.updated,
            unchanged: summary.unchanged,
            skipped: summary.skipped,
        }
    }
}
