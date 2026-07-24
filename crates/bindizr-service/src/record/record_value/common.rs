use bindizr_core::dns::name::{presentation_labels, to_fqdn_lowercase};

use crate::{
    error::ServiceError,
    validation::{MAX_DOMAIN_LEN, has_whitespace_or_control, validate_domain_label},
};

pub(super) fn reject_duplicate_priority_field(
    record_type: &str,
    fallback_priority: Option<i32>,
) -> Result<(), ServiceError> {
    if fallback_priority.is_some() {
        return Err(ServiceError::invalid_record_value(format!(
            "{record_type} priority must be provided either inline or in the priority field, not both"
        )));
    }

    Ok(())
}

pub(super) fn parse_optional_u16_record_field(
    field: &str,
    value: Option<i32>,
) -> Result<u16, ServiceError> {
    u16::try_from(value.unwrap_or(10)).map_err(|_| {
        ServiceError::invalid_record_value(format!("{field} must be between 0 and 65535"))
    })
}

pub(super) fn parse_u16_record_field(field: &str, value: &str) -> Result<u16, ServiceError> {
    value.parse::<u16>().map_err(|_| {
        ServiceError::invalid_record_value(format!(
            "{field} must be an unsigned 16-bit integer: {value}"
        ))
    })
}

pub(super) fn parse_u32_record_field(field: &str, value: &str) -> Result<u32, ServiceError> {
    value.parse::<u32>().map_err(|_| {
        ServiceError::invalid_record_value(format!(
            "{field} must be an unsigned 32-bit integer: {value}"
        ))
    })
}

pub(super) fn validate_domain_record_value(field: &str, value: &str) -> Result<(), ServiceError> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(ServiceError::invalid_record_value(format!(
            "{} must not be empty",
            field
        )));
    }

    if has_whitespace_or_control(value) {
        return Err(ServiceError::invalid_record_value(format!(
            "{} must not contain whitespace or control characters",
            field
        )));
    }

    let without_trailing_dot = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if without_trailing_dot.is_empty() {
        return Err(ServiceError::invalid_record_value(format!(
            "{} must not be the root zone",
            field
        )));
    }

    if without_trailing_dot.len() > MAX_DOMAIN_LEN {
        return Err(ServiceError::invalid_record_value(format!(
            "{} must be 253 bytes or fewer",
            field
        )));
    }

    for label in presentation_labels(without_trailing_dot)
        .map_err(|e| ServiceError::invalid_record_value(e.to_string()))?
    {
        validate_domain_label(&label, field, true, ServiceError::invalid_record_value)?;
    }

    Ok(())
}

pub(super) fn canonical_domain_value(value: &str) -> String {
    to_fqdn_lowercase(value)
}
