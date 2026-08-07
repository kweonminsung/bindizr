use super::value::{canonical_domain_value, validate_domain_record_value};

pub(crate) struct NsRecordValue<'a> {
    target: &'a str,
}

impl<'a> NsRecordValue<'a> {
    pub(crate) fn parse(value: &'a str) -> Result<Self, String> {
        validate_domain_record_value("NS record value", value)?;
        Ok(Self { target: value })
    }

    pub(crate) fn canonical(&self) -> String {
        canonical_domain_value(self.target)
    }
}
