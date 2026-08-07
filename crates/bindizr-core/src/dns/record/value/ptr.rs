use super::common::{canonical_domain_value, validate_domain_record_value};

pub(super) struct PtrRecordValue<'a> {
    target: &'a str,
}

impl<'a> PtrRecordValue<'a> {
    pub(super) fn parse(value: &'a str) -> Result<Self, String> {
        validate_domain_record_value("PTR record value", value)?;
        Ok(Self { target: value })
    }

    pub(super) fn canonical(&self) -> String {
        canonical_domain_value(self.target)
    }
}
