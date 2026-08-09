use super::value::{
    parse_optional_u16_record_field, parse_u16_record_field, validate_domain_record_value,
};
use crate::dns::name::to_fqdn_lowercase;

pub(crate) struct SrvRecordValue<'a> {
    priority: u16,
    weight: u16,
    port: u16,
    target: &'a str,
}

impl<'a> SrvRecordValue<'a> {
    /// The value is '<weight> <port> <target>'; the priority comes from the
    /// priority field (default 10), never inline.
    pub(crate) fn parse(value: &'a str, fallback_priority: Option<i32>) -> Result<Self, String> {
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

    /// The wire fields of a stored value: priority (from the column, default
    /// 10), weight, port, and target.
    pub(crate) fn wire_fields(
        value: &'a str,
        fallback_priority: Option<i32>,
    ) -> Result<(u16, u16, u16, &'a str), String> {
        let parsed = Self::parse(value, fallback_priority)?;
        Ok((parsed.priority, parsed.weight, parsed.port, parsed.target))
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.target.trim() == "." {
            return Ok(());
        }

        validate_domain_record_value("SRV record target", self.target)
    }

    pub(crate) fn canonical(&self) -> String {
        format!(
            "{} {} {} {}",
            self.priority,
            self.weight,
            self.port,
            to_fqdn_lowercase(self.target)
        )
    }

    /// The value column's form: `<weight> <port> <target>` with a lowercase
    /// FQDN target.
    pub(crate) fn encoded(&self) -> String {
        format!(
            "{} {} {}",
            self.weight,
            self.port,
            to_fqdn_lowercase(self.target)
        )
    }
}
