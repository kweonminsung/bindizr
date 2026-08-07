pub mod value;

use self::value::{TxtContent, TxtRdata};
use super::name::to_fqdn_lowercase;
use crate::model::record::RecordType;

/// Resolve a stored owner name to its display FQDN within `zone_name`.
pub fn display_record_owner_name(stored_name: &str, zone_name: &str) -> String {
    let zone_fqdn = to_fqdn_lowercase(zone_name);
    let trimmed = stored_name.trim();

    if trimmed == "@" {
        return zone_fqdn;
    }

    if trimmed.ends_with('.') {
        return to_fqdn_lowercase(trimmed);
    }

    let candidate = to_fqdn_lowercase(trimmed);
    if candidate == zone_fqdn || candidate.ends_with(&format!(".{}", zone_fqdn)) {
        candidate
    } else {
        to_fqdn_lowercase(&format!("{}.{}", trimmed, zone_fqdn))
    }
}

/// Format a stored record value for display according to its `record_type`.
pub fn display_record_value(value: &str, record_type: &RecordType) -> String {
    if *record_type == RecordType::TXT {
        return match TxtRdata::from_encoded(value).and_then(|rdata| rdata.to_content()) {
            Some(TxtContent::Single(value)) => value,
            Some(TxtContent::Segments(segments)) => segments.join(""),
            None => value.to_string(),
        };
    }

    match record_type {
        RecordType::CNAME | RecordType::NS | RecordType::PTR => to_fqdn_lowercase(value),
        RecordType::MX => display_last_name_field(value, MX_FIELD_COUNTS),
        RecordType::SRV => display_last_name_field(value, SRV_FIELD_COUNTS),
        _ => value.to_string(),
    }
}

// Priority may live in the separate column, so it can be omitted from the value:
// MX is `[priority] target`, SRV is `[priority] weight port target`.
const MX_FIELD_COUNTS: &[usize] = &[1, 2];
const SRV_FIELD_COUNTS: &[usize] = &[3, 4];

/// Render a stored value plus its priority column as zone-file rdata: MX/SRV
/// carry the priority inline (default 10), TXT is quoted per character-string,
/// and other types use their display form.
pub fn presentation_rdata(value: &str, priority: Option<i32>, record_type: &RecordType) -> String {
    match record_type {
        RecordType::TXT => txt_presentation(value),
        RecordType::MX | RecordType::SRV => {
            format!(
                "{} {}",
                priority.unwrap_or(10),
                display_record_value(value, record_type)
            )
        }
        _ => display_record_value(value, record_type),
    }
}

/// Render stored TXT RDATA as space-separated quoted character-strings,
/// escaping bytes per RFC 1035, Section 5.1.
fn txt_presentation(value: &str) -> String {
    match TxtRdata::from_encoded(value) {
        Some(rdata) => rdata.to_presentation(),
        // Not an encoded TXT value; quote it as a single character-string.
        None => quote_txt_charstr(value.as_bytes()),
    }
}

/// Render bytes as a quoted TXT character-string, escaping `"`/`\` and any
/// non-printable byte as a `\DDD` decimal escape (RFC 1035, Section 5.1).
pub fn quote_txt_charstr(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    for &byte in bytes {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(byte as char),
            _ => out.push_str(&format!("\\{:03}", byte)),
        }
    }
    out.push('"');
    out
}

fn display_last_name_field(value: &str, valid_field_counts: &[usize]) -> String {
    let mut fields = value
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();

    if !valid_field_counts.contains(&fields.len()) {
        return value.to_string();
    }

    let last = fields.pop().expect("valid field count guarantees a target");
    fields.push(to_fqdn_lowercase(&last));
    fields.join(" ")
}

#[cfg(test)]
mod tests;
