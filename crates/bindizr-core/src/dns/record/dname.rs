use super::{ParseRecordValueError, value::validate_domain_record_value};
use crate::dns::name::to_fqdn;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnameRecordValue<'a> {
    target: &'a str,
}

impl<'a> DnameRecordValue<'a> {
    /// Parse and validate a DNAME record value.
    pub fn parse(value: &'a str) -> Result<Self, ParseRecordValueError> {
        validate_domain_record_value("DNAME record value", value)?;
        Ok(Self { target: value })
    }

    /// Render the DNAME value in canonical text form.
    pub fn canonical(&self) -> String {
        to_fqdn(self.target)
    }
}

#[cfg(test)]
mod tests {
    use super::DnameRecordValue;

    /// Keep DNAME target case in stored and wire forms.
    #[test]
    fn preserves_target_case() {
        assert_eq!(
            DnameRecordValue::parse("Target.Example.COM")
                .unwrap()
                .canonical(),
            "Target.Example.COM."
        );
    }

    /// Verify rejection of invalid DNAME targets.
    #[test]
    fn rejects_a_target_that_is_not_a_name() {
        assert!(DnameRecordValue::parse("not a name").is_err());
    }
}
