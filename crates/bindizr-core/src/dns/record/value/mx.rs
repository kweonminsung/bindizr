use super::common::{
    canonical_domain_value, parse_optional_u16_record_field, validate_domain_record_value,
};

pub(super) struct MxRecordValue<'a> {
    priority: u16,
    target: &'a str,
}

impl<'a> MxRecordValue<'a> {
    /// The value is the target host only; the priority comes from the priority
    /// field (default 10), never inline.
    pub(super) fn parse(value: &'a str, fallback_priority: Option<i32>) -> Result<Self, String> {
        match value.split_whitespace().collect::<Vec<_>>().as_slice() {
            [target] => Ok(Self {
                priority: parse_optional_u16_record_field("MX priority", fallback_priority)?,
                target,
            }),
            _ => Err(format!(
                "MX record value must be the target host '<target>', with the priority in the priority field: {value}"
            )),
        }
    }

    pub(super) fn validate(&self) -> Result<(), String> {
        if self.target.trim() == "." {
            if self.priority != 0 {
                return Err("Null MX record target '.' must use priority 0".to_string());
            }
            return Ok(());
        }

        validate_domain_record_value("MX record target", self.target)
    }

    /// Null MX (RFC 7505): priority 0 with target `.`.
    pub(super) fn is_null(&self) -> bool {
        self.priority == 0 && self.target.trim() == "."
    }

    pub(super) fn canonical(&self) -> String {
        format!("{} {}", self.priority, canonical_domain_value(self.target))
    }
}
