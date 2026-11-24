use bindizr_service::types::{ImportZoneResponse, ImportZonesItemResponse};
use tabled::Tabled;

use crate::cli::output::display;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Tabled)]
pub(crate) struct ImportSummaryRow {
    /// The counts describe the plan, which a rejected file never applies.
    #[tabled(rename = "APPLIED", display = "display::display_yes_no")]
    pub(crate) applied: bool,
    #[tabled(rename = "DRY-RUN", display = "display::display_yes_no")]
    pub(crate) dry_run: bool,
    #[tabled(rename = "PARSED")]
    pub(crate) parsed: u64,
    #[tabled(rename = "ADDED")]
    pub(crate) added: u64,
    #[tabled(rename = "DELETED")]
    pub(crate) deleted: u64,
    #[tabled(rename = "UPDATED")]
    pub(crate) updated: u64,
    #[tabled(rename = "UNCHANGED")]
    pub(crate) unchanged: u64,
    #[tabled(rename = "SKIPPED")]
    pub(crate) skipped: u64,
}

impl From<&ImportZoneResponse> for ImportSummaryRow {
    /// Build a CLI table row from the import result.
    fn from(response: &ImportZoneResponse) -> Self {
        let summary = &response.summary;
        Self {
            applied: response.applied,
            dry_run: response.dry_run,
            parsed: summary.parsed,
            added: summary.added,
            deleted: summary.deleted,
            updated: summary.updated,
            unchanged: summary.unchanged,
            skipped: summary.skipped,
        }
    }
}

/// One zone of a bulk import, as the CLI table lists it.
#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct ImportZonesRow {
    #[tabled(rename = "ZONE")]
    pub(crate) zone_name: String,
    #[tabled(rename = "RESULT")]
    pub(crate) result: String,
    #[tabled(rename = "PARSED")]
    pub(crate) parsed: String,
    #[tabled(rename = "ADDED")]
    pub(crate) added: String,
    #[tabled(rename = "DELETED")]
    pub(crate) deleted: String,
    #[tabled(rename = "UPDATED")]
    pub(crate) updated: String,
    #[tabled(rename = "UNCHANGED")]
    pub(crate) unchanged: String,
    #[tabled(rename = "SKIPPED")]
    pub(crate) skipped: String,
    #[tabled(rename = "ERROR")]
    pub(crate) error: String,
}

impl From<&ImportZonesItemResponse> for ImportZonesRow {
    /// Build a CLI table row from one zone's outcome.
    fn from(zone_result: &ImportZonesItemResponse) -> Self {
        let summary = zone_result.import.as_ref().map(|import| import.summary);
        let count = |value: Option<u64>| display::display_option(&value);

        Self {
            zone_name: zone_result.zone_name.clone(),
            result: zone_result.result.to_string(),
            parsed: count(summary.map(|summary| summary.parsed)),
            added: count(summary.map(|summary| summary.added)),
            deleted: count(summary.map(|summary| summary.deleted)),
            updated: count(summary.map(|summary| summary.updated)),
            unchanged: count(summary.map(|summary| summary.unchanged)),
            skipped: count(summary.map(|summary| summary.skipped)),
            error: display::display_option(&zone_result.error.as_ref().map(|error| &error.error)),
        }
    }
}
