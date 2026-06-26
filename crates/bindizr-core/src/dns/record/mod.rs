use super::{name::to_fqdn_lowercase, txt};
use crate::model::record::RecordType;

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
        RecordType::MX | RecordType::SRV => display_last_name_field(value),
        _ => value.to_string(),
    }
}

fn display_last_name_field(value: &str) -> String {
    let mut fields = value
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let Some(last) = fields.pop() else {
        return value.to_string();
    };

    fields.push(to_fqdn_lowercase(&last));
    fields.join(" ")
}

#[cfg(test)]
mod tests;
