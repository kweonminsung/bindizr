//! Shared field parsing/validation helpers for stored record values.

use crate::dns::name::{
    MAX_DOMAIN_LEN, has_whitespace_or_control, presentation_labels, validate_domain_label,
};

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
