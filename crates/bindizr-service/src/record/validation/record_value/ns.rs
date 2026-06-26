use super::common::{canonical_domain_value, validate_domain_record_value};
use crate::error::ServiceError;

pub(super) struct NsRecordValue<'a> {
    target: &'a str,
}

impl<'a> NsRecordValue<'a> {
    pub(super) fn parse(value: &'a str) -> Result<Self, ServiceError> {
        validate_domain_record_value("NS record value", value)?;
        Ok(Self { target: value })
    }

    pub(super) fn canonical(&self) -> String {
        canonical_domain_value(self.target)
    }
}
