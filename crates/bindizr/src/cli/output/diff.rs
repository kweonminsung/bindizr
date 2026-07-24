//! Zone-file-style rendering of record changes, shared by snapshot diff and
//! the bulk/import previews. An entry is `{change, name, record_type, ttl,
//! from_rdata, to_rdata}`; a changed RRset stacks its removed values above its
//! added ones.
use serde_json::Value;

fn str_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Render the `+`/`-`/`~` lines for a list of diff entries (no summary footer).
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
        let ttl = entry
            .get("ttl")
            .and_then(|v| v.as_i64())
            .map_or_else(|| "-".to_string(), |ttl| ttl.to_string());

        let from = str_array(entry.get("from_rdata"));
        let to = str_array(entry.get("to_rdata"));
        let values: Vec<String> = match change {
            "added" => to,
            "removed" => from,
            // Changed: only the delta, removed values first then added ones.
            _ => {
                let mut delta: Vec<String> =
                    from.iter().filter(|v| !to.contains(v)).cloned().collect();
                delta.extend(to.iter().filter(|v| !from.contains(v)).cloned());
                delta
            }
        };

        let prefix = format!("{} {:<24} {:>5} IN {:<6} ", sign, name, ttl, rtype);
        let pad = " ".repeat(prefix.chars().count());
        out.push_str(&format!(
            "{}{}\n",
            prefix,
            values.first().map(String::as_str).unwrap_or("")
        ));
        for value in values.iter().skip(1) {
            out.push_str(&format!("{}{}\n", pad, value));
        }
    }
    out
}

/// Fold flat add/delete changes (as returned by import) into diff entries,
/// pairing an add and a delete on the same RRset into a single `changed`.
pub(crate) fn changes_to_entries(changes: &[Value]) -> Vec<Value> {
    // Preserve first-seen order so the output is stable.
    let mut order: Vec<(String, String)> = Vec::new();
    let mut grouped: std::collections::HashMap<(String, String), (Vec<Value>, Vec<Value>)> =
        std::collections::HashMap::new();

    for change in changes {
        let name = change.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let rtype = change
            .get("record_type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let key = (name.to_string(), rtype.to_string());
        let entry = grouped.entry(key.clone()).or_insert_with(|| {
            order.push(key.clone());
            (Vec::new(), Vec::new())
        });
        let rdata = change
            .get("rdata")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let ttl = change.get("ttl").cloned().unwrap_or(Value::Null);
        match change.get("op").and_then(|v| v.as_str()) {
            Some("delete") => entry.0.push(Value::Array(vec![Value::String(rdata), ttl])),
            _ => entry.1.push(Value::Array(vec![Value::String(rdata), ttl])),
        }
    }

    order
        .into_iter()
        .map(|key| {
            let (removed, added) = grouped.remove(&key).unwrap();
            let rdata_of =
                |rows: &[Value]| -> Vec<Value> { rows.iter().map(|row| row[0].clone()).collect() };
            // TTL for the line: any row's ttl (added preferred, else removed).
            let ttl = added
                .first()
                .or_else(|| removed.first())
                .map(|row| row[1].clone())
                .unwrap_or(Value::Null);
            let change = match (removed.is_empty(), added.is_empty()) {
                (true, false) => "added",
                (false, true) => "removed",
                _ => "changed",
            };
            serde_json::json!({
                "change": change,
                "name": key.0,
                "record_type": key.1,
                "ttl": ttl,
                "from_rdata": rdata_of(&removed),
                "to_rdata": rdata_of(&added),
            })
        })
        .collect()
}

/// Render a preview of pending changes: the diff lines plus a summary footer.
pub(crate) fn render_change_preview(entries: &[Value]) -> String {
    let (mut added, mut removed, mut changed) = (0usize, 0usize, 0usize);
    for entry in entries {
        match entry.get("change").and_then(|v| v.as_str()) {
            Some("added") => added += 1,
            Some("removed") => removed += 1,
            _ => changed += 1,
        }
    }
    let mut out = render_diff_lines(entries);
    out.push('\n');
    out.push_str(&format!("Records: +{} -{} ~{}\n", added, removed, changed));
    out
}
