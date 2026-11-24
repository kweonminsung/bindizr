use bindizr_core::dns::{Serial, SoaInterval, Ttl};
use bindizr_service::types::{RollbackZoneResponse, VersionRecordResponse, ZoneVersionResponse};
use tabled::Tabled;

use crate::cli::output::display;

#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct VersionRow {
    #[tabled(rename = "SERIAL")]
    pub(crate) serial: Serial,
    #[tabled(rename = "MNAME")]
    pub(crate) mname: String,
    #[tabled(rename = "RNAME")]
    pub(crate) rname: String,
    #[tabled(rename = "DEFAULT-TTL")]
    pub(crate) default_ttl: i64,
    #[tabled(rename = "REFRESH")]
    pub(crate) refresh: SoaInterval,
    #[tabled(rename = "RETRY")]
    pub(crate) retry: SoaInterval,
    #[tabled(rename = "EXPIRE")]
    pub(crate) expire: SoaInterval,
    #[tabled(rename = "MINIMUM-TTL")]
    pub(crate) minimum_ttl: i64,
    #[tabled(rename = "SOURCE")]
    pub(crate) source: String,
    #[tabled(rename = "CHANGED-BY")]
    pub(crate) actor: String,
    #[tabled(rename = "CREATED-AT")]
    pub(crate) created_at: String,
}

impl From<&ZoneVersionResponse> for VersionRow {
    /// Build a CLI table row from the zone version response.
    fn from(version: &ZoneVersionResponse) -> Self {
        Self {
            serial: version.serial,
            mname: version.mname.clone(),
            rname: version.rname.clone(),
            default_ttl: i64::from(version.default_ttl),
            refresh: version.refresh,
            retry: version.retry,
            expire: version.expire,
            minimum_ttl: i64::from(version.minimum_ttl),
            source: version.source.to_string(),
            actor: display::display_option(&version.actor),
            created_at: display::display_time(version.created_at),
        }
    }
}

/// Table row for records rewound to a version serial (no database id).
#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct VersionRecordRow {
    #[tabled(rename = "NAME")]
    pub(crate) name: String,
    #[tabled(rename = "TYPE")]
    pub(crate) record_type: String,
    #[tabled(rename = "VALUE")]
    pub(crate) value: String,
    #[tabled(rename = "TTL")]
    pub(crate) ttl: Ttl,
    #[tabled(rename = "PRIORITY", display = "display::display_option")]
    pub(crate) priority: Option<i32>,
}

impl From<&VersionRecordResponse> for VersionRecordRow {
    /// Build a CLI table row from the version record response.
    fn from(record: &VersionRecordResponse) -> Self {
        Self {
            name: record.name.clone(),
            record_type: record.record_type.to_string(),
            value: display::display_record_value(&record.value),
            ttl: record.ttl,
            priority: record.priority,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Tabled)]
pub(crate) struct RollbackSummaryRow {
    #[tabled(rename = "TARGET-SERIAL")]
    pub(crate) target_serial: Serial,
    #[tabled(rename = "NEW-SERIAL")]
    pub(crate) new_serial: Serial,
    #[tabled(rename = "APPLIED", display = "display::display_yes_no")]
    pub(crate) applied: bool,
    #[tabled(rename = "DRY-RUN", display = "display::display_yes_no")]
    pub(crate) dry_run: bool,
    #[tabled(rename = "ADDED")]
    pub(crate) added: u64,
    #[tabled(rename = "DELETED")]
    pub(crate) deleted: u64,
    #[tabled(rename = "UNCHANGED")]
    pub(crate) unchanged: u64,
    #[tabled(rename = "SOA-CHANGED", display = "display::display_yes_no")]
    pub(crate) soa_changed: bool,
}

impl From<&RollbackZoneResponse> for RollbackSummaryRow {
    /// Build a CLI table row from the zone rollback summary.
    fn from(response: &RollbackZoneResponse) -> Self {
        Self {
            target_serial: response.target_serial,
            new_serial: response.new_serial,
            applied: response.applied,
            dry_run: response.dry_run,
            added: response.summary.added,
            deleted: response.summary.deleted,
            unchanged: response.summary.unchanged,
            soa_changed: response.summary.soa_changed,
        }
    }
}
