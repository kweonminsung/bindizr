use super::common::{
    canonical_domain_value, parse_optional_u16_record_field, parse_u16_record_field,
    reject_duplicate_priority_field, validate_domain_record_value,
};
use crate::error::ServiceError;

pub(super) struct MxRecordValue<'a> {
    pub(super) priority: u16,
    pub(super) target: &'a str,
}

impl<'a> MxRecordValue<'a> {
    pub(super) fn parse(
        value: &'a str,
        fallback_priority: Option<i32>,
    ) -> Result<Self, ServiceError> {
        let fields = value.split_whitespace().collect::<Vec<_>>();
        match fields.as_slice() {
            [priority, target] => {
                reject_duplicate_priority_field("MX", fallback_priority)?;
                Ok(Self {
                    priority: parse_u16_record_field("MX priority", priority)?,
                    target,
                })
            }
            [target] => Ok(Self {
                priority: parse_optional_u16_record_field("MX priority", fallback_priority)?,
                target,
            }),
            _ => Err(ServiceError::BadRequest(format!(
                "MX record value must be '<priority> <target>' or '<target>': {value}"
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
            return Err(ServiceError::BadRequest(
                "Null MX record target '.' must use priority 0".to_string(),
            ));
        }
        return Ok(());
    }

    validate_domain_record_value("MX record target", target)
}
