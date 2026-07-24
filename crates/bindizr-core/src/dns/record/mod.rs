use super::{name::to_fqdn_lowercase, txt};
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
        return match txt::decode_raw_txt_value(value) {
            Some(txt::DecodedTxtValue::String(value)) => value,
            Some(txt::DecodedTxtValue::Segments(segments)) => segments.join(""),
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

/// Render TXT from the stored raw RDATA so non-UTF-8 character-strings survive
/// export → import. Working from the raw bytes (not the decoded string, which
/// fails on non-UTF-8) each byte is emitted verbatim when printable ASCII and
/// as a `\DDD` decimal escape otherwise (RFC 1035, Section 5.1).
fn txt_presentation(value: &str) -> String {
    let Some(rdata) = txt::decode_raw_txt_rdata(value) else {
        // Not an encoded TXT value; quote it as a single character-string.
        return quote_txt_charstr(value.as_bytes());
    };

    let mut segments = Vec::new();
    let mut pos = 0;
    while pos < rdata.len() {
        let len = rdata[pos] as usize;
        pos += 1;
        segments.push(quote_txt_charstr(&rdata[pos..pos + len]));
        pos += len;
    }
    if segments.is_empty() {
        segments.push("\"\"".to_string());
    }
    segments.join(" ")
}

fn quote_txt_charstr(bytes: &[u8]) -> String {
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
