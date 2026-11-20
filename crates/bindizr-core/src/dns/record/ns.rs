use crate::dns::name;
use crate::dns::record::{ParseRecordValueError, value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NsRecordValue<'a> {
    target: &'a str,
}

impl<'a> NsRecordValue<'a> {
    /// Parse and validate a NS record value.
    pub fn parse(value: &'a str) -> Result<Self, ParseRecordValueError> {
        value::validate_domain_record_value("NS record value", value)?;

        Ok(Self { target: value })
    }

    /// Render the NS value in canonical text form.
    pub fn canonical(self) -> String {
        name::to_fqdn_lowercase(self.target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the root and a literal dot label retain different wire names.
    #[test]
    fn ns_accepts_root_target_and_preserves_literal_dot() {
        for (input, expected) in [(".", vec![0]), (r"\.", vec![1, b'.', 0])] {
            let value = NsRecordValue::parse(input).unwrap();
            assert_eq!(name::encode_name(&value.canonical()).unwrap(), expected);
        }

        for invalid in ["", ".."] {
            assert!(NsRecordValue::parse(invalid).is_err(), "{invalid:?}");
        }
    }
}
