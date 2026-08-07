use super::value::validate_domain_record_value;
use crate::dns::name::to_fqdn_lowercase;

pub(crate) struct NsRecordValue<'a> {
    target: &'a str,
}

impl<'a> NsRecordValue<'a> {
    pub(crate) fn parse(value: &'a str) -> Result<Self, String> {
        validate_domain_record_value("NS record value", value)?;
        Ok(Self { target: value })
    }

    pub(crate) fn canonical(&self) -> String {
        to_fqdn_lowercase(self.target)
    }
}
