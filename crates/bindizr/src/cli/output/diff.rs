//! Client-side rendering of a `RecordDiff` as a zone-file `+`/`-`/`~` patch:
//! the API sends structured records, and rdata assembly lives here.
use bindizr_core::dns::record::TxtRecordValue;
use bindizr_service::types::{RecordDiffEntry, RecordDiffValue, RecordValueRequest};

use crate::cli::output::color;

/// Render one record's value as zone-file rdata: MX/SRV carry the priority
/// inline, TXT is quoted per character-string, other types use the value as-is.
fn rdata(record: &RecordDiffValue, record_type: &str) -> String {
    let segments: &[String] = match &record.value {
        RecordValueRequest::String(value) => std::slice::from_ref(value),
        RecordValueRequest::Segments(segments) => segments,
    };

    match record_type {
        "TXT" => segments
            .iter()
            .map(|segment| TxtRecordValue::to_quoted_charstr(segment.as_bytes()))
            .collect::<Vec<_>>()
            .join(" "),
        "MX" | "SRV" => format!("{} {}", record.priority.unwrap_or(10), segments.concat()),
        _ => segments.concat(),
    }
}

/// Render the `+`/`-`/`~` lines for a diff's entries (no summary footer). A
/// changed RRset stacks its removed records above its added ones.
pub(crate) fn render_diff_lines(entries: &[RecordDiffEntry]) -> String {
    let mut out = String::new();
    for entry in entries {
        let sign = match entry.change.as_str() {
            "added" => '+',
            "removed" => '-',
            _ => '~',
        };
        let rtype = entry.record_type.as_str();

        // Show only the delta: records removed, then records added.
        let rendered = |value: &RecordDiffValue| (value.ttl.to_string(), rdata(value, rtype));
        let from_lines: Vec<(String, String)> = entry.from.iter().map(rendered).collect();
        let to_lines: Vec<(String, String)> = entry.to.iter().map(rendered).collect();
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

        // Sign and name label the RRset once; TTL stays per-line so a TTL-only
        // change reads clearly.
        for (index, (ttl, data)) in lines.iter().enumerate() {
            let head = if index == 0 { sign } else { ' ' };
            let name_col = if index == 0 { entry.name.as_str() } else { "" };
            let line = format!(
                "{} {:<24} {:>5} IN {:<6} {}",
                head, name_col, ttl, rtype, data
            );
            let line = if index < removed {
                color::red(&line)
            } else {
                color::green(&line)
            };
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

fn count(entries: &[RecordDiffEntry], change: &str) -> usize {
    entries.iter().filter(|e| e.change == change).count()
}

/// Render a preview of a diff: the change lines plus a summary footer.
pub(crate) fn render_change_preview(entries: &[RecordDiffEntry]) -> String {
    let mut out = render_diff_lines(entries);
    out.push('\n');
    out.push_str(&format!(
        "Records: {} {} {}\n",
        color::green(&format!("+{}", count(entries, "added"))),
        color::red(&format!("-{}", count(entries, "removed"))),
        color::yellow(&format!("~{}", count(entries, "changed")))
    ));
    out
}
