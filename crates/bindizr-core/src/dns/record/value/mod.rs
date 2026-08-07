//! Cross-type helpers for stored record values: shared parsing/validation
//! helpers and owner-name display rendering.

use crate::dns::name::{
    MAX_DOMAIN_LEN, has_whitespace_or_control, presentation_labels, to_fqdn_lowercase,
    validate_domain_label,
};

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

pub(crate) fn parse_optional_u16_record_field(
    field: &str,
    value: Option<i32>,
) -> Result<u16, String> {
    u16::try_from(value.unwrap_or(10)).map_err(|_| format!("{field} must be between 0 and 65535"))
}

pub(crate) fn parse_u16_record_field(field: &str, value: &str) -> Result<u16, String> {
    value
        .parse::<u16>()
        .map_err(|_| format!("{field} must be an unsigned 16-bit integer: {value}"))
}

pub(crate) fn parse_u32_record_field(field: &str, value: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|_| format!("{field} must be an unsigned 32-bit integer: {value}"))
}

pub(crate) fn validate_domain_record_value(field: &str, value: &str) -> Result<(), String> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(format!("{} must not be empty", field));
    }

    if has_whitespace_or_control(value) {
        return Err(format!(
            "{} must not contain whitespace or control characters",
            field
        ));
    }

    let without_trailing_dot = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if without_trailing_dot.is_empty() {
        return Err(format!("{} must not be the root zone", field));
    }

    if without_trailing_dot.len() > MAX_DOMAIN_LEN {
        return Err(format!("{} must be 253 bytes or fewer", field));
    }

    for label in presentation_labels(without_trailing_dot).map_err(|e| e.to_string())? {
        validate_domain_label(&label, field, true, |message| message)?;
    }

    Ok(())
}

pub(crate) fn canonical_domain_value(value: &str) -> String {
    to_fqdn_lowercase(value)
}

#[cfg(test)]
mod tests;
