use super::value::validate_domain_record_value;
use crate::dns::name::to_fqdn_lowercase;

pub(crate) struct PtrRecordValue<'a> {
    target: &'a str,
}

impl<'a> PtrRecordValue<'a> {
    pub(crate) fn parse(value: &'a str) -> Result<Self, String> {
        validate_domain_record_value("PTR record value", value)?;
        Ok(Self { target: value })
    }

    pub(crate) fn canonical(&self) -> String {
        to_fqdn_lowercase(self.target)
    }
}
