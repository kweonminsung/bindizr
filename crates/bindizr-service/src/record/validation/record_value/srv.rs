use super::common::{
    canonical_domain_value, parse_optional_u16_record_field, parse_u16_record_field,
    reject_duplicate_priority_field, validate_domain_record_value,
};
use crate::error::ServiceError;

pub(super) struct SrvRecordValue<'a> {
    priority: u16,
    weight: u16,
    port: u16,
    target: &'a str,
}

impl<'a> SrvRecordValue<'a> {
    pub(super) fn parse(
        value: &'a str,
        fallback_priority: Option<i32>,
    ) -> Result<Self, ServiceError> {
        let fields = value.split_whitespace().collect::<Vec<_>>();
        match fields.as_slice() {
            [priority, weight, port, target] => {
                reject_duplicate_priority_field("SRV", fallback_priority)?;
                Ok(Self {
                    priority: parse_u16_record_field("SRV priority", priority)?,
                    weight: parse_u16_record_field("SRV weight", weight)?,
                    port: parse_u16_record_field("SRV port", port)?,
                    target,
                })
            }
            [weight, port, target] => Ok(Self {
                priority: parse_optional_u16_record_field("SRV priority", fallback_priority)?,
                weight: parse_u16_record_field("SRV weight", weight)?,
                port: parse_u16_record_field("SRV port", port)?,
                target,
            }),
            _ => Err(ServiceError::BadRequest(format!(
                "SRV record value must be '<priority> <weight> <port> <target>' or '<weight> <port> <target>': {value}"
            ))),
        }
    }

    pub(super) fn validate(&self) -> Result<(), ServiceError> {
        validate_srv_record_target(self.target)
    }

    pub(super) fn canonical(&self) -> String {
        format!(
            "{} {} {} {}",
            self.priority,
            self.weight,
            self.port,
            canonical_domain_value(self.target)
        )
    }
}

fn validate_srv_record_target(target: &str) -> Result<(), ServiceError> {
    if target.trim() == "." {
        return Ok(());
    }

    validate_domain_record_value("SRV record target", target)
}
