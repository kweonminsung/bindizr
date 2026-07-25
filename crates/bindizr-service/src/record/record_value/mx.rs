use super::common::{
    canonical_domain_value, parse_optional_u16_record_field, validate_domain_record_value,
};
use crate::error::ServiceError;

pub(super) struct MxRecordValue<'a> {
    pub(super) priority: u16,
    pub(super) target: &'a str,
}

impl<'a> MxRecordValue<'a> {
    /// The value is the target host only; the priority comes from the priority
    /// field (default 10), never inline.
    pub(super) fn parse(
        value: &'a str,
        fallback_priority: Option<i32>,
    ) -> Result<Self, ServiceError> {
        match value.split_whitespace().collect::<Vec<_>>().as_slice() {
            [target] => Ok(Self {
                priority: parse_optional_u16_record_field("MX priority", fallback_priority)?,
                target,
            }),
            _ => Err(ServiceError::invalid_record_value(format!(
                "MX record value must be the target host '<target>', with the priority in the priority field: {value}"
            ))),
        }
    }

    pub(super) fn validate(&self) -> Result<(), ServiceError> {
        validate_mx_record_target(self.target, self.priority)
    }

    pub(super) fn canonical(&self) -> String {
        format!("{} {}", self.priority, canonical_domain_value(self.target))
    }
}

fn validate_mx_record_target(target: &str, priority: u16) -> Result<(), ServiceError> {
    if target.trim() == "." {
        if priority != 0 {
            return Err(ServiceError::invalid_record_value(
                "Null MX record target '.' must use priority 0".to_string(),
            ));
        }
        return Ok(());
    }

    validate_domain_record_value("MX record target", target)
}
