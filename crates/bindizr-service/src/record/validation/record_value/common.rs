use bindizr_core::dns::name::{split_presentation_labels, to_fqdn};

use super::super::{MAX_DNS_LABEL_LEN, MAX_DOMAIN_LEN, has_whitespace_or_control};
use crate::error::ServiceError;

pub(super) fn reject_duplicate_priority_field(
    record_type: &str,
    fallback_priority: Option<i32>,
) -> Result<(), ServiceError> {
    if fallback_priority.is_some() {
        return Err(ServiceError::BadRequest(format!(
            "{record_type} priority must be provided either inline or in the priority field, not both"
        )));
    }

    Ok(())
}

pub(super) fn parse_optional_u16_record_field(
    field: &str,
    value: Option<i32>,
) -> Result<u16, ServiceError> {
    u16::try_from(value.unwrap_or(10))
        .map_err(|_| ServiceError::BadRequest(format!("{field} must be between 0 and 65535")))
}

pub(super) fn parse_u16_record_field(field: &str, value: &str) -> Result<u16, ServiceError> {
    value.parse::<u16>().map_err(|_| {
        ServiceError::BadRequest(format!(
            "{field} must be an unsigned 16-bit integer: {value}"
        ))
    })
}

pub(super) fn validate_domain_record_value(field: &str, value: &str) -> Result<(), ServiceError> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(ServiceError::BadRequest(format!(
            "{} must not be empty",
            field
        )));
    }

    if has_whitespace_or_control(trimmed) {
        return Err(ServiceError::BadRequest(format!(
            "{} must not contain whitespace or control characters",
            field
        )));
    }

    let without_trailing_dot = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if without_trailing_dot.is_empty() {
        return Err(ServiceError::BadRequest(format!(
            "{} must not be the root zone",
            field
        )));
    }

    if without_trailing_dot.len() > MAX_DOMAIN_LEN {
        return Err(ServiceError::BadRequest(format!(
            "{} must be 253 bytes or fewer",
            field
        )));
    }

    for label in split_presentation_labels(without_trailing_dot)
        .map_err(|e| ServiceError::BadRequest(e.to_string()))?
    {
        validate_domain_record_label(field, &label)?;
    }

    Ok(())
}

fn validate_domain_record_label(field: &str, label: &str) -> Result<(), ServiceError> {
    if label.is_empty() {
        return Err(ServiceError::BadRequest(format!(
            "{} must not contain empty labels",
            field
        )));
    }

    if label.len() > MAX_DNS_LABEL_LEN {
        return Err(ServiceError::BadRequest(format!(
            "{} labels must be 63 bytes or fewer",
            field
        )));
    }

    if !label
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ServiceError::BadRequest(format!(
            "{} labels must contain only ASCII letters, digits, hyphens, or underscores",
            field
        )));
    }

    if label.starts_with('-') || label.ends_with('-') {
        return Err(ServiceError::BadRequest(format!(
            "{} labels must not start or end with hyphens",
            field
        )));
    }

    Ok(())
}

pub(super) fn canonical_domain_value(value: &str) -> String {
    to_fqdn(value).to_ascii_lowercase()
}
