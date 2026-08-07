use super::common::{
    canonical_domain_value, parse_optional_u16_record_field, parse_u16_record_field,
    validate_domain_record_value,
};

pub(super) struct SrvRecordValue<'a> {
    priority: u16,
    weight: u16,
    port: u16,
    target: &'a str,
}

impl<'a> SrvRecordValue<'a> {
    /// The value is '<weight> <port> <target>'; the priority comes from the
    /// priority field (default 10), never inline.
    pub(super) fn parse(value: &'a str, fallback_priority: Option<i32>) -> Result<Self, String> {
        match value.split_whitespace().collect::<Vec<_>>().as_slice() {
            [weight, port, target] => Ok(Self {
                priority: parse_optional_u16_record_field("SRV priority", fallback_priority)?,
                weight: parse_u16_record_field("SRV weight", weight)?,
                port: parse_u16_record_field("SRV port", port)?,
                target,
            }),
            _ => Err(format!(
                "SRV record value must be '<weight> <port> <target>', with the priority in the priority field: {value}"
            )),
        }
    }

    pub(super) fn validate(&self) -> Result<(), String> {
        if self.target.trim() == "." {
            return Ok(());
        }

        validate_domain_record_value("SRV record target", self.target)
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
