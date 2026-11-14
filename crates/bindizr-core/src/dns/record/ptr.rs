use super::ParseRecordValueError;
use crate::dns::name;
use crate::dns::record::value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtrRecordValue<'a> {
    target: &'a str,
}

impl<'a> PtrRecordValue<'a> {
    /// Parse and validate a PTR record value.
    pub fn parse(value: &'a str) -> Result<Self, ParseRecordValueError> {
        // RFC 2181, Section 11 allows root targets.
        if value != "." {
            value::validate_domain_record_value("PTR record value", value)?;
        }
        Ok(Self { target: value })
    }

    /// Render the PTR value in canonical text form.
    pub fn canonical(self) -> String {
        name::to_fqdn_lowercase(self.target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::name;

    /// Verify that root targets stay distinct from literal dot labels.
    #[test]
    fn ptr_accepts_root_target_and_preserves_literal_dot() {
        for (input, expected) in [(".", vec![0]), (r"\.", vec![1, b'.', 0])] {
            let value = PtrRecordValue::parse(input).unwrap();
            assert_eq!(name::encode_name(&value.canonical()).unwrap(), expected);
        }

        for invalid in ["", ".."] {
            assert!(PtrRecordValue::parse(invalid).is_err(), "{invalid:?}");
        }
    }
}
