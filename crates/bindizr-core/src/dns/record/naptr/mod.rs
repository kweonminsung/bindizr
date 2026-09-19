mod regexp;

use regexp::validate_naptr_regexp;

use super::{
    Rdata, to_quoted_charstr,
    value::{parse_char_string, parse_u16_record_field, validate_domain_record_value},
};
use crate::dns::name::{encode_name, to_fqdn_lowercase};

pub struct NaptrRecordValue<'a> {
    order: u16,
    preference: u16,
    flags: String,
    services: String,
    regexp: String,
    replacement: &'a str,
}

impl<'a> NaptrRecordValue<'a> {
    /// `<order> <preference> "<flags>" "<services>" "<regexp>" <replacement>`
    /// (RFC 3403, Section 4.1). Both numbers stay inline; NAPTR orders by two
    /// fields, so neither fits the single priority column.
    pub fn parse(value: &'a str) -> Result<Self, String> {
        let rest = value.trim_start();
        let (order, rest) = parse_field("NAPTR order", rest)?;
        let (preference, rest) = parse_field("NAPTR preference", rest)?;
        let (flags, rest) = parse_char_string("NAPTR flags", rest)?;
        let (services, rest) = parse_char_string("NAPTR services", rest)?;
        let (regexp, rest) = parse_char_string("NAPTR regexp", rest)?;

        let replacement = rest.trim();
        if replacement.is_empty() || replacement.split_whitespace().count() != 1 {
            return Err(format!(
                "NAPTR record value must be '<order> <preference> \"<flags>\" \"<services>\" \"<regexp>\" <replacement>': {value}"
            ));
        }

        Ok(Self {
            order: parse_u16_record_field("NAPTR order", order)?,
            preference: parse_u16_record_field("NAPTR preference", preference)?,
            flags,
            services,
            regexp,
            replacement,
        })
    }

    /// The wire-format RDATA of a stored value (RFC 3403, Section 4.1).
    pub(crate) fn to_rdata(&self) -> Result<Rdata, String> {
        let mut rdata = Vec::with_capacity(4);
        rdata.extend_from_slice(&self.order.to_be_bytes());
        rdata.extend_from_slice(&self.preference.to_be_bytes());
        for (field, text) in [
            ("NAPTR flags", &self.flags),
            ("NAPTR services", &self.services),
            ("NAPTR regexp", &self.regexp),
        ] {
            let len = u8::try_from(text.len())
                .map_err(|_| format!("{field} must be 255 bytes or less"))?;
            rdata.push(len);
            rdata.extend_from_slice(text.as_bytes());
        }
        rdata.extend_from_slice(&encode_name(self.replacement)?);
        Rdata::new(rdata)
    }

    /// Validate the fields of this NAPTR value.
    pub fn validate(&self) -> Result<(), String> {
        validate_naptr_regexp(&self.regexp)?;

        // The replacement is a name or the root, which ends the rewrite chain.
        if self.replacement == "." {
            return Ok(());
        }
        // RFC 3403, Section 4.1: the two are mutually exclusive.
        if !self.regexp.is_empty() {
            return Err(
                "NAPTR record replacement must be '.' when the regexp is set (RFC 3403, Section 4.1)"
                    .to_string(),
            );
        }

        validate_domain_record_value("NAPTR record replacement", self.replacement)
    }

    /// Render the NAPTR value in canonical text form.
    pub fn canonical(&self) -> String {
        format!(
            "{} {} {} {} {} {}",
            self.order,
            self.preference,
            to_quoted_charstr(self.flags.as_bytes()),
            to_quoted_charstr(self.services.as_bytes()),
            to_quoted_charstr(self.regexp.as_bytes()),
            to_fqdn_lowercase(self.replacement)
        )
    }

    /// A record decoded off the wire, whose character-strings are still the raw
    /// octets of RFC 3403, Section 4.1.
    pub(crate) fn from_wire(
        order: u16,
        preference: u16,
        flags: &[u8],
        services: &[u8],
        regexp: &[u8],
        replacement: &'a str,
    ) -> Result<Self, String> {
        let to_text = |field: &str, bytes: &[u8]| {
            std::str::from_utf8(bytes)
                .map(str::to_string)
                .map_err(|_| format!("{field} must be valid UTF-8"))
        };

        Ok(Self {
            order,
            preference,
            flags: to_text("NAPTR flags", flags)?,
            services: to_text("NAPTR services", services)?,
            regexp: to_text("NAPTR regexp", regexp)?,
            replacement,
        })
    }
}

/// One whitespace-separated field and the rest of the value.
fn parse_field<'a>(field: &str, input: &'a str) -> Result<(&'a str, &'a str), String> {
    let end = input
        .find(char::is_whitespace)
        .ok_or_else(|| format!("NAPTR record value ends before {field}"))?;

    Ok((&input[..end], input[end..].trim_start()))
}

#[cfg(test)]
mod tests {
    use super::NaptrRecordValue;

    /// Verify NAPTR parsing and replacement-name canonicalization.
    #[test]
    fn parses_the_presentation_form_and_canonicalizes_the_replacement() {
        let parsed =
            NaptrRecordValue::parse("100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.Example.COM.")
                .unwrap();

        assert_eq!(
            parsed.canonical(),
            "100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.example.com."
        );
    }

    /// Verify that a root replacement ends the rewrite chain.
    #[test]
    fn a_root_replacement_ends_the_rewrite_chain() {
        let value = "200 20 \"u\" \"E2U+tel\" \"!^.*$!tel:+1!\" .";
        let parsed = NaptrRecordValue::parse(value).unwrap();

        parsed.validate().unwrap();
        assert_eq!(parsed.canonical(), value);
    }

    /// Verify conversion of NAPTR wire data into its stored form.
    #[test]
    fn reads_a_wire_record_back_into_the_stored_form() {
        assert_eq!(
            NaptrRecordValue::from_wire(100, 10, b"S", b"SIP+D2U", b"", "_sip._udp.Example.COM")
                .unwrap()
                .canonical(),
            "100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.example.com."
        );
        assert_eq!(
            NaptrRecordValue::from_wire(200, 20, b"u", b"E2U+tel", b"!^.*$!tel:+1!", ".")
                .unwrap()
                .canonical(),
            "200 20 \"u\" \"E2U+tel\" \"!^.*$!tel:+1!\" ."
        );
    }

    /// Verify that a regexp may carry quotes and escapes.
    #[test]
    fn a_regexp_may_carry_quotes_and_escapes() {
        let parsed = NaptrRecordValue::parse(r#"1 1 "u" "E2U+sip" "!\"a\"!sip:b!" ."#).unwrap();

        assert_eq!(parsed.canonical(), r#"1 1 "u" "E2U+sip" "!\"a\"!sip:b!" ."#);
    }

    /// Verify that a regexp BIND refuses fails validation, not just parsing.
    #[test]
    fn a_regexp_bind_refuses_fails_validation() {
        let parsed = NaptrRecordValue::parse("10 10 \"u\" \"E2U+sip\" \"garbage\" .").unwrap();

        let err = parsed.validate().unwrap_err();
        assert!(err.starts_with("NAPTR regexp"), "{err}");
    }

    /// Verify that a regexp and a replacement name together are rejected.
    #[test]
    fn a_regexp_and_a_replacement_name_together_are_rejected() {
        // RFC 3403, Section 4.1 makes the two mutually exclusive.
        let parsed =
            NaptrRecordValue::parse("10 10 \"u\" \"E2U+sip\" \"!^.*$!sip:x!\" next.example.")
                .unwrap();

        assert!(parsed.validate().is_err());
    }

    /// Verify rejection of NAPTR values with missing fields.
    #[test]
    fn rejects_a_value_missing_a_field() {
        for value in [
            "100 10 \"S\" \"SIP+D2U\" \"\"",
            "100 \"S\" \"SIP+D2U\" \"\" .",
            "100 10 S \"SIP+D2U\" \"\" .",
            "100 10 \"S\" \"SIP+D2U\" \"\" a.example.com b.example.com",
        ] {
            assert!(
                NaptrRecordValue::parse(value).is_err(),
                "{value} was accepted"
            );
        }
    }
}
