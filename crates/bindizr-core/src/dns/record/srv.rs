use super::{
    Rdata,
    value::{
        DEFAULT_PRIORITY, parse_optional_u16_record_field, parse_u16_record_field,
        validate_domain_record_value,
    },
};
use crate::dns::name::{encode_name, to_fqdn_lowercase};

pub struct SrvRecordValue<'a> {
    priority: u16,
    weight: u16,
    port: u16,
    target: &'a str,
}

impl<'a> SrvRecordValue<'a> {
    /// The value is `<weight> <port> <target>`; the priority comes from the
    /// priority field (default 10), never inline.
    pub fn parse(value: &'a str, fallback_priority: Option<i32>) -> Result<Self, String> {
        match value.split_whitespace().collect::<Vec<_>>().as_slice() {
            [weight, port, target] => Ok(Self {
                priority: parse_optional_u16_record_field(
                    "SRV priority",
                    fallback_priority,
                    DEFAULT_PRIORITY,
                )?,
                weight: parse_u16_record_field("SRV weight", weight)?,
                port: parse_u16_record_field("SRV port", port)?,
                target,
            }),
            _ => Err(format!(
                "SRV record value must be '<weight> <port> <target>', with the priority in the priority field: {value}"
            )),
        }
    }

    /// The wire-format RDATA of a stored value (RFC 2782).
    pub fn to_rdata(&self) -> Result<Rdata, String> {
        let mut rdata = Vec::with_capacity(6);
        rdata.extend_from_slice(&self.priority.to_be_bytes());
        rdata.extend_from_slice(&self.weight.to_be_bytes());
        rdata.extend_from_slice(&self.port.to_be_bytes());
        rdata.extend_from_slice(&encode_name(self.target)?);
        Rdata::new(rdata)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.target.trim() == "." {
            return Ok(());
        }

        validate_domain_record_value("SRV record target", self.target)
    }

    pub fn canonical(&self) -> String {
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
    pub fn encoded(&self) -> String {
        format!(
            "{} {} {}",
            self.weight,
            self.port,
            to_fqdn_lowercase(self.target)
        )
    }
}
