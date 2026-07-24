//! Zone-file-style rendering of a `RecordDiff`, shared by snapshot diff and the
//! bulk/import previews. The server sends structured records (display value +
//! priority); this module assembles the zone-file rdata and the `+`/`-`/`~`
//! lines — presentation lives entirely on the client.
use serde_json::Value;

/// Render one record's value as zone-file rdata: MX/SRV carry the priority
/// inline, TXT is quoted per character-string, other types use the value as-is.
fn rdata(value: &Value, record_type: &str) -> String {
    let priority = value.get("priority").and_then(|v| v.as_i64());
    let raw = value.get("value");
    match record_type {
        "TXT" => {
            let segments: Vec<String> = match raw {
                Some(Value::Array(arr)) => arr
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect(),
                Some(Value::String(s)) => vec![s.clone()],
                _ => Vec::new(),
            };
            segments
                .iter()
                .map(|segment| {
                    let escaped = segment.replace('\\', "\\\\").replace('"', "\\\"");
                    format!("\"{}\"", escaped)
                })
                .collect::<Vec<_>>()
                .join(" ")
        }
        "MX" | "SRV" => format!(
            "{} {}",
            priority.unwrap_or(10),
            raw.and_then(|v| v.as_str()).unwrap_or("")
        ),
        _ => raw.and_then(|v| v.as_str()).unwrap_or("").to_string(),
    }
}

/// A record's TTL, or `-` when unset (the RRset inherits the zone TTL).
fn ttl_of(value: &Value) -> String {
    value
        .get("ttl")
        .and_then(|v| v.as_i64())
        .map_or_else(|| "-".to_string(), |ttl| ttl.to_string())
}

/// Render the `+`/`-`/`~` lines for a diff's entries (no summary footer). A
/// changed RRset stacks its removed records above its added ones.
pub(crate) fn render_diff_lines(entries: &[Value]) -> String {
    let mut out = String::new();
    for entry in entries {
        let change = entry.get("change").and_then(|v| v.as_str()).unwrap_or("");
        let sign = match change {
            "added" => '+',
            "removed" => '-',
            _ => '~',
        };
        let name = entry.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let rtype = entry
            .get("record_type")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let empty = vec![];
        let from = entry
            .get("from")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty);
        let to = entry.get("to").and_then(|v| v.as_array()).unwrap_or(&empty);
        // Show only the delta: records removed, then records added.
        let rendered = |value: &Value| (ttl_of(value), rdata(value, rtype));
        let from_lines: Vec<(String, String)> = from.iter().map(rendered).collect();
        let to_lines: Vec<(String, String)> = to.iter().map(rendered).collect();
        let mut lines: Vec<(String, String)> = from_lines
            .iter()
            .filter(|line| !to_lines.contains(line))
            .cloned()
            .collect();
        lines.extend(
            to_lines
                .iter()
                .filter(|line| !from_lines.contains(line))
                .cloned(),
        );

        // Sign and owner name label the RRset once; each record keeps its own
        // TTL so a TTL-only change reads clearly.
        for (index, (ttl, data)) in lines.iter().enumerate() {
            let head = if index == 0 { sign } else { ' ' };
            let name_col = if index == 0 { name } else { "" };
            out.push_str(&format!(
                "{} {:<24} {:>5} IN {:<6} {}\n",
                head, name_col, ttl, rtype, data
            ));
        }
    }
    out
}

fn count(entries: &[Value], change: &str) -> usize {
    entries
        .iter()
        .filter(|e| e.get("change").and_then(|v| v.as_str()) == Some(change))
        .count()
}

/// Render a preview of a diff: the change lines plus a summary footer.
pub(crate) fn render_change_preview(entries: &[Value]) -> String {
    let mut out = render_diff_lines(entries);
    out.push('\n');
    out.push_str(&format!(
        "Records: +{} -{} ~{}\n",
        count(entries, "added"),
        count(entries, "removed"),
        count(entries, "changed")
    ));
    out
}
