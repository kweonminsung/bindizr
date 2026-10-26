use super::{ParseRecordValueError, value};
use crate::dns::name;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CnameRecordValue<'a> {
    target: &'a str,
}

impl<'a> CnameRecordValue<'a> {
    /// Parse and validate a CNAME record value.
    pub fn parse(value: &'a str) -> Result<Self, ParseRecordValueError> {
        // RFC 2181, Section 11 allows root targets.
        if value != "." {
            value::validate_domain_record_value("CNAME record value", value)?;
        }
        Ok(Self { target: value })
    }

    /// Render a CNAME target in canonical text form.
    pub fn canonical(&self) -> String {
        name::to_fqdn_lowercase(self.target)
    }
}

#[cfg(test)]
mod tests {
    use super::CnameRecordValue;

    /// Keep root targets distinct from literal dot labels.
    #[test]
    fn cname_accepts_root_target_and_preserves_literal_dot() {
        use crate::dns::name;

        for (input, expected) in [(".", vec![0]), (r"\.", vec![1, b'.', 0])] {
            let value = CnameRecordValue::parse(input).unwrap();
            assert_eq!(name::encode_name(&value.canonical()).unwrap(), expected);
        }

        for invalid in ["", ".."] {
            assert!(CnameRecordValue::parse(invalid).is_err(), "{invalid:?}");
        }
    }

    /// Render a CNAME target in canonical text form.
    fn canonical(value: &str) -> String {
        CnameRecordValue::parse(value).unwrap().canonical()
    }

    /// Verify that an escaped dot stays inside its label.
    #[test]
    fn cname_preserves_escaped_dot_inside_label() {
        // RFC 1035, Section 5.1: the escape makes the dot data, so the name has
        // two labels and the trailing dot is the only boundary left to drop.
        assert_eq!(canonical(r"Evil\.Example.COM."), r"evil\046example.com.");
        assert_eq!(canonical(r"a\.b"), r"a\046b.");
    }

    /// Verify that a label keeps what only an escape could have spelled.
    #[test]
    fn cname_preserves_escaped_label_octets() {
        assert_eq!(canonical(r"host\065.example.com"), "hosta.example.com.");
        assert_eq!(canonical(r"a\\b.example.com"), r"a\\b.example.com.");
    }

    /// Verify that a classless reverse delegation target survives.
    #[test]
    fn cname_accepts_classless_reverse_delegation_target() {
        // RFC 2317, Section 4 delegates through a label carrying a slash.
        assert_eq!(
            canonical("1.0/25.2.0.192.in-addr.arpa."),
            "1.0/25.2.0.192.in-addr.arpa."
        );
    }
}
