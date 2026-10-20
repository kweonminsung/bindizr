use super::{ParseRecordValueError, value::validate_domain_record_value};
use crate::dns::name::to_fqdn_lowercase;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtrRecordValue<'a> {
    target: &'a str,
}

impl<'a> PtrRecordValue<'a> {
    /// Parse and validate a PTR record value.
    pub fn parse(value: &'a str) -> Result<Self, ParseRecordValueError> {
        // RFC 2181, Section 11 allows root targets.
        if value != "." {
            validate_domain_record_value("PTR record value", value)?;
        }
        Ok(Self { target: value })
    }

    /// Render the PTR value in canonical text form.
    pub fn canonical(&self) -> String {
        to_fqdn_lowercase(self.target)
    }
}

#[cfg(test)]
mod tests {
    use super::PtrRecordValue;

    /// Keep root targets distinct from literal dot labels.
    #[test]
    fn ptr_accepts_root_target_and_preserves_literal_dot() {
        use crate::dns::name::encode_name;

        for (input, expected) in [(".", vec![0]), (r"\.", vec![1, b'.', 0])] {
            let value = PtrRecordValue::parse(input).unwrap();
            assert_eq!(encode_name(&value.canonical()).unwrap(), expected);
        }
        for invalid in ["", ".."] {
            assert!(PtrRecordValue::parse(invalid).is_err(), "{invalid:?}");
        }
    }
}
