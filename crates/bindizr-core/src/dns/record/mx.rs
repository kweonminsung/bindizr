use super::{
    Rdata,
    value::{DEFAULT_PRIORITY, parse_optional_u16_record_field, validate_domain_record_value},
};
use crate::dns::name::{encode_name, to_fqdn_lowercase};

pub struct MxRecordValue<'a> {
    priority: u16,
    target: &'a str,
}

impl<'a> MxRecordValue<'a> {
    /// Whether a stored value plus its priority column denotes a null MX
    /// (RFC 7505): priority 0 with target `.`.
    pub fn is_null_value(value: &str, priority: Option<i32>) -> bool {
        MxRecordValue::parse(value, priority)
            .map(|parsed| parsed.is_null())
            .unwrap_or(false)
    }

    /// The value is the target host only; the priority comes from the priority
    /// field (default 10), never inline.
    pub fn parse(value: &'a str, fallback_priority: Option<i32>) -> Result<Self, String> {
        match value.split_whitespace().collect::<Vec<_>>().as_slice() {
            [target] => Ok(Self {
                priority: parse_optional_u16_record_field(
                    "MX priority",
                    fallback_priority,
                    DEFAULT_PRIORITY,
                )?,
                target,
            }),
            _ => Err(format!(
                "MX record value must be the target host '<target>', with the priority in the priority field: {value}"
            )),
        }
    }

    /// The wire-format RDATA of a stored value (RFC 1035, Section 3.3.9).
    pub fn to_rdata(&self) -> Result<Rdata, String> {
        let mut rdata = self.priority.to_be_bytes().to_vec();
        rdata.extend_from_slice(&encode_name(self.target)?);
        Rdata::new(rdata)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.target.trim() == "." {
            if self.priority != 0 {
                return Err("Null MX record target '.' must use priority 0".to_string());
            }
            return Ok(());
        }

        validate_domain_record_value("MX record target", self.target)
    }

    /// Null MX (RFC 7505): priority 0 with target `.`.
    pub fn is_null(&self) -> bool {
        self.priority == 0 && self.target.trim() == "."
    }

    pub fn canonical(&self) -> String {
        format!("{} {}", self.priority, to_fqdn_lowercase(self.target))
    }

    /// The value column's form: the target host as a lowercase FQDN.
    pub fn encoded(&self) -> String {
        to_fqdn_lowercase(self.target)
    }
}
