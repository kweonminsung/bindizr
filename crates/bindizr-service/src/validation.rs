use bindizr_core::dns::name::split_presentation_labels;
pub(crate) use bindizr_core::dns::name::{MAX_DNS_LABEL_LEN, MAX_DOMAIN_LEN};

use crate::error::ServiceError;

pub(crate) fn has_whitespace_or_control(value: &str) -> bool {
    value
        .chars()
        .any(|c| c.is_ascii_control() || c.is_whitespace())
}

/// Ensure every label of a domain name is non-empty and at most 63 bytes.
pub(crate) fn validate_wire_labels(name: &str, field: &str) -> Result<(), ServiceError> {
    for label in split_presentation_labels(name.trim_end_matches('.'))
        .map_err(|e| ServiceError::BadRequest(e.to_string()))?
    {
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
    }

    Ok(())
}
