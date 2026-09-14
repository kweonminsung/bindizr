use super::value::validate_domain_record_value;
use crate::dns::name::to_fqdn_lowercase;

pub struct DnameRecordValue<'a> {
    target: &'a str,
}

impl<'a> DnameRecordValue<'a> {
    /// Parse and validate a DNAME record value.
    pub fn parse(value: &'a str) -> Result<Self, String> {
        validate_domain_record_value("DNAME record value", value)?;
        Ok(Self { target: value })
    }

    /// Render the DNAME value in canonical text form.
    pub fn canonical(&self) -> String {
        to_fqdn_lowercase(self.target)
    }
}

#[cfg(test)]
mod tests {
    use super::DnameRecordValue;

    /// Verify that DNAME targets use CNAME-compatible canonicalization.
    #[test]
    fn canonicalizes_the_target_like_cname() {
        assert_eq!(
            DnameRecordValue::parse("Target.Example.COM")
                .unwrap()
                .canonical(),
            "target.example.com."
        );
    }

    /// Verify rejection of invalid DNAME targets.
    #[test]
    fn rejects_a_target_that_is_not_a_name() {
        assert!(DnameRecordValue::parse("not a name").is_err());
    }
}
