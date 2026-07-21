use bindizr_core::dns::name::presentation_labels;
pub(crate) use bindizr_core::dns::name::{MAX_DNS_LABEL_LEN, MAX_DOMAIN_LEN};

use crate::error::ServiceError;

pub(crate) fn has_whitespace_or_control(value: &str) -> bool {
    value
        .chars()
        .any(|c| c.is_ascii_control() || c.is_whitespace())
}

/// Ensure a domain name fits the 253-byte presentation limit and every label is
/// non-empty and at most 63 bytes.
pub(crate) fn validate_wire_labels(name: &str, field: &str) -> Result<(), ServiceError> {
    let name = name.trim_end_matches('.');

    if name.len() > MAX_DOMAIN_LEN {
        return Err(ServiceError::invalid_input(format!(
            "{} must be 253 bytes or fewer",
            field
        )));
    }

    for label in
        presentation_labels(name).map_err(|e| ServiceError::invalid_input(e.to_string()))?
    {
        if label.is_empty() {
            return Err(ServiceError::invalid_input(format!(
                "{} must not contain empty labels",
                field
            )));
        }

        if label.len() > MAX_DNS_LABEL_LEN {
            return Err(ServiceError::invalid_input(format!(
                "{} labels must be 63 bytes or fewer",
                field
            )));
        }
    }

    Ok(())
}
