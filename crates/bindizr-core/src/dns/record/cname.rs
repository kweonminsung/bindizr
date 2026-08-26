use super::value::validate_domain_record_value;
use crate::dns::name::to_fqdn_lowercase;

pub struct CnameRecordValue<'a> {
    target: &'a str,
}

impl<'a> CnameRecordValue<'a> {
    pub fn parse(value: &'a str) -> Result<Self, String> {
        validate_domain_record_value("CNAME record value", value)?;
        Ok(Self { target: value })
    }

    pub fn canonical(&self) -> String {
        to_fqdn_lowercase(self.target)
    }
}
