use super::value::validate_domain_record_value;
use crate::dns::name::to_fqdn_lowercase;

pub struct CnameRecordValue<'a> {
    target: &'a str,
}

impl<'a> CnameRecordValue<'a> {
    /// Parse and validate a CNAME record value.
    pub fn parse(value: &'a str) -> Result<Self, String> {
        validate_domain_record_value("CNAME record value", value)?;
        Ok(Self { target: value })
    }

    /// Render a CNAME target in canonical text form.
    pub fn canonical(&self) -> String {
        to_fqdn_lowercase(self.target)
    }
}

#[cfg(test)]
mod tests {
    use super::CnameRecordValue;

    /// Render a CNAME target in canonical text form.
    fn canonical(value: &str) -> String {
        CnameRecordValue::parse(value).unwrap().canonical()
    }

    /// Verify that an escaped dot stays inside its label.
    #[test]
    fn an_escaped_dot_stays_inside_its_label() {
        // RFC 1035, Section 5.1: the escape makes the dot data, so the name has
        // two labels and the trailing dot is the only boundary left to drop.
        assert_eq!(canonical(r"Evil\.Example.COM."), r"evil\.example.com.");
        assert_eq!(canonical(r"a\.b"), r"a\.b.");
    }

    /// Verify that a label keeps what only an escape could have spelled.
    #[test]
    fn a_label_keeps_what_only_an_escape_could_have_spelled() {
        assert_eq!(canonical(r"host\065.example.com"), "hosta.example.com.");
        assert_eq!(canonical(r"a\\b.example.com"), r"a\\b.example.com.");
    }

    /// Verify that a classless reverse delegation target survives.
    #[test]
    fn a_classless_reverse_delegation_target_survives() {
        // RFC 2317, Section 4 delegates through a label carrying a slash.
        assert_eq!(
            canonical("1.0/25.2.0.192.in-addr.arpa."),
            "1.0/25.2.0.192.in-addr.arpa."
        );
    }
}
