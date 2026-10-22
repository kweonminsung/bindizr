use super::{ParseRecordValueError, value::validate_domain_record_value};
use crate::dns::name::to_fqdn;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnameRecordValue<'a> {
    target: &'a str,
}

impl<'a> DnameRecordValue<'a> {
    /// Parse and validate a DNAME record value.
    pub fn parse(value: &'a str) -> Result<Self, ParseRecordValueError> {
        // RFC 2181, Section 11 allows root targets.
        if value != "." {
            validate_domain_record_value("DNAME record value", value)?;
        }
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

    /// Keep root targets distinct from literal dot labels.
    #[test]
    fn dname_accepts_root_target_and_preserves_literal_dot() {
        use crate::dns::name::encode_name;

        for (input, expected) in [(".", vec![0]), (r"\.", vec![1, b'.', 0])] {
            let value = DnameRecordValue::parse(input).unwrap();
            assert_eq!(encode_name(&value.canonical()).unwrap(), expected);
        }

        for invalid in ["", ".."] {
            assert!(DnameRecordValue::parse(invalid).is_err(), "{invalid:?}");
        }
    }

    /// Keep DNAME target case in stored and wire forms.
    #[test]
    fn dname_preserves_target_case() {
        assert_eq!(
            DnameRecordValue::parse("Target.Example.COM")
                .unwrap()
                .canonical(),
            "Target.Example.COM."
        );
    }

    /// Verify rejection of invalid DNAME targets.
    #[test]
    fn dname_rejects_invalid_target_name() {
        assert!(DnameRecordValue::parse("not a name").is_err());
    }
}
