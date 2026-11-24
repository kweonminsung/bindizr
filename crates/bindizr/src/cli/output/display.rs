//! Shared CLI cells for absent values, flags, time, truncation, and combined fields.
//! Use a type's `Display` where available.

use std::fmt;

use bindizr_core::dns::{DnsTransport, Serial};
use bindizr_core::model::activity_log::ActivityTarget;
use bindizr_core::model::transfer::{TransferKind, TransferResult};
use bindizr_service::types::{
    AccessLogResponse, RecordValue, SecondaryStatus, TransferLogResponse, TransferSummaryResponse,
};
use chrono::{DateTime, Utc};

/// What a cell shows for a value that is absent.
pub(crate) const MISSING_CELL: &str = "-";

/// The longest value a listing cell shows: one DKIM key would otherwise widen
/// the column for every row. `record get` and `-o json` carry the whole value.
const MAX_CELL_CHARS: usize = 48;

/// Render an optional value as one cell, absent as `-`.
pub(crate) fn display_option<T: fmt::Display>(value: &Option<T>) -> String {
    value
        .as_ref()
        .map_or_else(|| MISSING_CELL.to_string(), ToString::to_string)
}

/// Render a boolean as yes or no.
pub(crate) fn display_yes_no(value: &bool) -> String {
    if *value {
        "yes"
    } else {
        "no"
    }
    .to_string()
}

/// Render the serial distance behind the zone, negative when ahead; unordered
/// values show `-`.
pub(crate) fn display_serial_lag(
    zone_serial: Serial,
    visible_serial: Option<Serial>,
    status: SecondaryStatus,
) -> String {
    match (status, visible_serial) {
        (SecondaryStatus::InSync, Some(_)) => "0".to_string(),
        (SecondaryStatus::Lagging, Some(visible)) => zone_serial.distance_from(visible).to_string(),
        (SecondaryStatus::Ahead, Some(visible)) => {
            (-i64::from(visible.distance_from(zone_serial))).to_string()
        }
        (SecondaryStatus::Reachable | SecondaryStatus::Unreachable, _) | (_, None) => {
            MISSING_CELL.to_string()
        }
    }
}

/// Render a timestamp for table output; `-o json` carries the full precision.
pub(crate) fn display_time(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Render an optional timestamp for table output.
pub(crate) fn display_option_time(value: &Option<DateTime<Utc>>) -> String {
    value.map_or_else(|| MISSING_CELL.to_string(), display_time)
}

/// Render a record value as one listing cell, cut at `MAX_CELL_CHARS` and marked
/// when it was; counted in characters, so a multi-byte value is not split.
pub(crate) fn display_record_value(value: &RecordValue) -> String {
    let text = value.to_string();
    let mut chars = text.chars();
    let head: String = chars.by_ref().take(MAX_CELL_CHARS).collect();

    if chars.next().is_none() {
        head
    } else {
        format!("{head}…")
    }
}

/// Render uptime as days, hours, minutes, and seconds; an unset start
/// time means the front ends are still starting.
pub(crate) fn display_uptime(started_at_ms: Option<u64>) -> String {
    let Some(started_at_ms) = started_at_ms else {
        return "starting".to_string();
    };

    let now_ms = u64::try_from(Utc::now().timestamp_millis()).unwrap_or(0);
    let secs = now_ms.saturating_sub(started_at_ms) / 1000;
    let (days, hours, minutes, seconds) = (
        secs / 86400,
        secs % 86400 / 3600,
        secs % 3600 / 60,
        secs % 60,
    );

    match (days, hours, minutes) {
        (0, 0, 0) => format!("{seconds}s"),
        (0, 0, _) => format!("{minutes}m {seconds}s"),
        (0, _, _) => format!("{hours}h {minutes}m"),
        _ => format!("{days}d {hours}h"),
    }
}

/// Render what a request asked as one cell: its method and its path or zone.
pub(crate) fn display_access_request(log: &AccessLogResponse) -> String {
    format!("{} {}", log.method, log.target)
}

/// Render the known identifiers that name an activity target.
pub(crate) fn display_activity_target(target: &ActivityTarget) -> String {
    let record_id = target.record_id.map(|id| format!("#{id}"));
    let label = [
        target.zone_name.as_deref(),
        target.name.as_deref(),
        target.record_name.as_deref(),
        target.record_type.as_deref(),
        record_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ");

    if label.is_empty() {
        MISSING_CELL.to_string()
    } else {
        label
    }
}

/// Render a transfer's response kind or unsuccessful result.
fn display_transfer_description(transfer: &TransferLogResponse) -> String {
    match (transfer.result, transfer.kind, transfer.incremental) {
        (TransferResult::Ok, TransferKind::Ixfr, true) => format!("{} delta", transfer.kind),
        (TransferResult::Ok, TransferKind::Ixfr, false) => format!("{} full", transfer.kind),
        (TransferResult::Ok, kind, _) => kind.to_string(),
        (result, _, _) => result.to_string(),
    }
}

/// Render a served transfer as one cell: what it was, the serial reached, when, and
/// `over TLS` when it was.
pub(crate) fn display_transfer(transfer: &TransferLogResponse) -> String {
    let over_tls = match transfer.transport {
        DnsTransport::Tls => " over TLS",
        DnsTransport::Udp | DnsTransport::Tcp => "",
    };
    format!(
        "{} {} at {}{over_tls}",
        display_transfer_description(transfer),
        display_option(&transfer.serial),
        display_time(transfer.created_at)
    )
}

/// Render how a secondary's zones were last served.
pub(crate) fn display_transfer_summary(summary: &TransferSummaryResponse) -> String {
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
        failed = TransferResult::Failed
    )
}
