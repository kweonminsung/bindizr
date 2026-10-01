//! One cell of CLI output for what no type of ours renders itself: an absent
//! value, a flag, a timestamp, a duration, a cut value, and a cell built from
//! several fields. A value with a `Display` is written with `{}` instead.

use bindizr_core::model::transfer::{TransferKind, TransferResult};
use bindizr_service::types::{RecordValueRequest, TransferResponse, TransferSummary};
use chrono::Utc;

/// What a cell shows for a value that is absent.
pub(crate) const MISSING_CELL: &str = "-";

/// An optional value as one cell, absent as `-`.
pub(crate) fn display_option<T: std::fmt::Display>(opt: &Option<T>) -> String {
    opt.as_ref()
        .map_or_else(|| MISSING_CELL.to_string(), ToString::to_string)
}

/// Render a boolean as yes or no.
pub(crate) fn display_yes_no(value: &bool) -> String {
    if *value { "yes" } else { "no" }.to_string()
}

/// The longest value a listing cell shows: one DKIM key would otherwise widen
/// the column for every row. `record get` and `-o json` carry the whole value.
const MAX_CELL_CHARS: usize = 48;

/// Format a timestamp for table output; `-o json` carries the full precision.
pub(crate) fn display_time(at: chrono::DateTime<chrono::Utc>) -> String {
    at.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Format an optional timestamp for table output.
pub(crate) fn display_option_time(opt: &Option<chrono::DateTime<chrono::Utc>>) -> String {
    opt.map_or_else(|| MISSING_CELL.to_string(), display_time)
}

/// A record value as one listing cell, cut at `MAX_CELL_CHARS` and marked
/// when it was; counted in characters, so a multi-byte value is not split.
pub(crate) fn display_record_value(value: &RecordValueRequest) -> String {
    let text = value.to_text();
    let mut chars = text.chars();
    let head: String = chars.by_ref().take(MAX_CELL_CHARS).collect();
    if chars.next().is_none() {
        head
    } else {
        format!("{}…", head)
    }
}

/// Format uptime as days, hours, minutes, and seconds; an unset start
/// time means the front ends are still starting.
pub(crate) fn display_uptime(started_at_ms: u64) -> String {
    if started_at_ms == 0 {
        return "starting".to_string();
    }
    let now_ms = Utc::now().timestamp_millis().max(0) as u64;
    let secs = now_ms.saturating_sub(started_at_ms) / 1000;
    let (days, hours, minutes, seconds) = (
        secs / 86_400,
        secs % 86_400 / 3_600,
        secs % 3_600 / 60,
        secs % 60,
    );
    match (days, hours, minutes) {
        (0, 0, 0) => format!("{}s", seconds),
        (0, 0, _) => format!("{}m {}s", minutes, seconds),
        (0, _, _) => format!("{}h {}m", hours, minutes),
        _ => format!("{}d {}h", days, hours),
    }
}

/// What a transfer was: the kind and whether a delta, or that it was refused
/// or failed.
pub(crate) fn display_transfer_kind(transfer: &TransferResponse) -> String {
    match (transfer.result, transfer.kind, transfer.incremental) {
        (TransferResult::Ok, TransferKind::Ixfr, true) => format!("{} delta", transfer.kind),
        (TransferResult::Ok, TransferKind::Ixfr, false) => format!("{} full", transfer.kind),
        (TransferResult::Ok, kind, _) => kind.to_string(),
        (result, _, _) => result.to_string(),
    }
}

/// A served transfer as one cell: what it was, the serial reached, and when.
pub(crate) fn display_transfer(transfer: &TransferResponse) -> String {
    format!(
        "{} {} at {}",
        display_transfer_kind(transfer),
        display_option(&transfer.serial),
        display_time(transfer.at)
    )
}

/// How a secondary's zones were last served.
pub(crate) fn display_transfer_summary(summary: &TransferSummary) -> String {
    if summary.zones == 0 {
        return "no transfers".to_string();
    }
    format!(
        "{} zones: {} {ixfr} delta, {} {ixfr} full, {} {axfr}, {} {refused}, {} {failed}",
        summary.zones,
        summary.ixfr_delta,
        summary.ixfr_full,
        summary.axfr,
        summary.refused,
        summary.failed,
        ixfr = TransferKind::Ixfr,
        axfr = TransferKind::Axfr,
        refused = TransferResult::Refused,
        failed = TransferResult::Failed,
    )
}
