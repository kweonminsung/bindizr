use bindizr_core::dns::name::classify_wire_labels;
pub(crate) use bindizr_core::dns::name::has_whitespace_or_control;

use crate::error::ServiceError;

/// [`classify_wire_labels`] with the rejection phrased against `field`.
pub(crate) fn validate_wire_labels(name: &str, field: &str) -> Result<(), ServiceError> {
    classify_wire_labels(name).map_err(|e| ServiceError::invalid_input(format!("{} {}", field, e)))
}
