//! Render structured record diffs as zone-file `+`/`-`/`~` patches.

use std::slice;

use bindizr_core::dns::record;
use bindizr_service::types::{
    DiffZoneVersionsResponse, RecordChange, RecordDiffEntryResponse, RecordDiffResponse,
    RecordDiffValueResponse, RecordValue,
};

use crate::cli::output::color;

/// Render one record's value as zone-file rdata: MX/SRV carry the priority
/// inline, TXT is quoted per character-string, other types use the value as-is.
fn display_rdata(diff_value: &RecordDiffValueResponse, record_type: &str) -> String {
    match record_type {
        "TXT" => {
            let segments: &[String] = match &diff_value.value {
                RecordValue::Text(value) => slice::from_ref(value),
                RecordValue::Segments(segments) => segments,
                RecordValue::Presentation { presentation } => return presentation.clone(),
            };
            segments
                .iter()
                .map(|segment| record::to_quoted_charstr(segment.as_bytes()))
                .collect::<Vec<_>>()
                .join(" ")
        }
        "MX" | "SRV" => format!(
            "{} {}",
            diff_value.priority.unwrap_or(10),
            diff_value.value.to_text()
        ),
        _ => diff_value.value.to_text(),
    }
}

/// Render the `+`/`-`/`~` lines for a diff's entries (no summary footer). A
/// changed entry stacks its removed records above its added ones.
fn render_diff_lines(entries: &[RecordDiffEntryResponse]) -> String {
    let mut rendered = String::new();

    for entry in entries {
        let sign = entry.change.to_string();
        let record_type = entry.record_type.as_str();

        // Show only the delta: records removed, then records added.
        let render_line = |value: &RecordDiffValueResponse| {
            (value.ttl.to_string(), display_rdata(value, record_type))
        };
        let from_lines: Vec<(String, String)> = entry.from.iter().map(render_line).collect();
        let to_lines: Vec<(String, String)> = entry.to.iter().map(render_line).collect();
        let mut lines: Vec<(String, String)> = from_lines
            .iter()
            .filter(|line| !to_lines.contains(line))
            .cloned()
            .collect();
        let removed = lines.len();
        lines.extend(
            to_lines
                .iter()
                .filter(|line| !from_lines.contains(line))
                .cloned(),
        );

        // Sign and name label the entry once; TTL stays per-line so a TTL-only
        // change reads clearly.
        for (index, (ttl, data)) in lines.iter().enumerate() {
            let head = if index == 0 {
                sign.as_str()
            } else {
                " "
            };
            let name_cell = if index == 0 {
                entry.name.as_str()
            } else {
                ""
            };
            let line = format!("{head} {name_cell:<24} {ttl:>5} IN {record_type:<6} {data}");
            let line = if index < removed {
                color::red(&line)
            } else {
                color::green(&line)
            };
            rendered.push_str(&line);
            rendered.push('\n');
        }
    }

    rendered
}

/// Render a preview of a diff: the change lines plus a summary footer.
pub(crate) fn render_change_preview(diff: &RecordDiffResponse) -> String {
    let mut rendered = render_diff_lines(&diff.entries);
    let summary = &diff.summary;
    rendered.push('\n');
    rendered.push_str(&format!(
        "By name and type: {} {} {}\n",
        color::green(&format!("{}{}", RecordChange::Added, summary.added)),
        color::red(&format!("{}{}", RecordChange::Removed, summary.removed)),
        color::yellow(&format!("{}{}", RecordChange::Changed, summary.changed))
    ));

    rendered
}

/// Render a version diff: the `+`/`-`/`~` lines plus SOA-serial and count footers.
pub(crate) fn render_version_diff(response: &DiffZoneVersionsResponse) -> String {
    let mut rendered = render_diff_lines(&response.diff.entries);
    let summary = &response.diff.summary;

    rendered.push('\n');
    rendered.push_str(&format!(
        "SOA serial: {} -> {}\n",
        response.from_serial, response.to_serial
    ));
    rendered.push_str(&format!(
        "By name and type: {}{} {}{} {}{}\n",
        RecordChange::Added,
        summary.added,
        RecordChange::Removed,
        summary.removed,
        RecordChange::Changed,
        summary.changed
    ));

    rendered
}
