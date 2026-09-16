//! CAA record values (RFC 8659): which certificate authorities may issue for
//! a name.

use super::{
    Rdata, to_quoted_charstr,
    value::{MAX_RECORD_RDATA, parse_quoted_string, parse_u8_record_field},
};

pub struct CaaRecordValue<'a> {
    flags: u8,
    tag: &'a str,
    value: String,
}

impl<'a> CaaRecordValue<'a> {
    /// The value is `<flags> <tag> <value>`; the value keeps its surrounding
    /// quotes optional, as presentation form allows both. Fields may be
    /// separated by runs of whitespace, as aligned zone files spell them.
    pub fn parse(value: &'a str) -> Result<Self, String> {
        let err = || format!("CAA record value must be '<flags> <tag> <value>': {value}");
        let (flags, rest) = value
            .trim()
            .split_once(char::is_whitespace)
            .ok_or_else(err)?;
        let (tag, rest) = rest
            .trim_start()
            .split_once(char::is_whitespace)
            .ok_or_else(err)?;
        let rest = rest.trim();

        // A quoted value resolves its escapes; a bare one has none, and keeps
        // the whitespace an unquoted value may carry.
        let value = if rest.starts_with('"') {
            let (text, trailing) = parse_quoted_string("CAA value", rest)?;
            if !trailing.is_empty() {
                return Err(err());
            }
            text
        } else {
            rest.to_string()
        };

        Ok(Self {
            flags: parse_u8_record_field("CAA flags", flags)?,
            tag,
            value,
        })
    }

    /// Validate the fields of this CAA value.
    pub fn validate(&self) -> Result<(), String> {
        // RFC 8659, Section 4.1: a tag is 1-15 alphanumeric characters.
        if self.tag.is_empty()
            || self.tag.len() > 15
            || !self.tag.chars().all(|c| c.is_ascii_alphanumeric())
        {
            return Err(format!(
                "CAA tag must be 1-15 alphanumeric characters: {}",
                self.tag
            ));
        }
        if self.value.is_empty() {
            return Err("CAA value must not be empty".to_string());
        }
        if self.value.chars().any(|c| c.is_control()) {
            return Err("CAA value must not contain control characters".to_string());
        }
        // Bounded so the record fits one transfer message beside the flags and
        // length-prefixed tag; enforced here so a stored row cannot poison an AXFR.
        let max_value = MAX_RECORD_RDATA - 2 - self.tag.len();
        if self.value.len() > max_value {
            return Err(format!(
                "CAA value must be at most {} bytes, got {}",
                max_value,
                self.value.len()
            ));
        }
        Ok(())
    }

    /// Render the CAA value in canonical text form.
    pub fn canonical(&self) -> String {
        format!(
            "{} {} {}",
            self.flags,
            self.tag.to_lowercase(),
            to_quoted_charstr(self.value.as_bytes())
        )
    }

    /// The wire-format RDATA of a stored value (RFC 8659, Section 5.1).
    pub(crate) fn to_rdata(&self) -> Result<Rdata, String> {
        let tag_len = u8::try_from(self.tag.len())
            .map_err(|_| format!("CAA tag must be 1-15 alphanumeric characters: {}", self.tag))?;
        let mut rdata = Vec::with_capacity(2 + self.tag.len() + self.value.len());
        rdata.push(self.flags);
        rdata.push(tag_len);
        rdata.extend_from_slice(self.tag.as_bytes());
        rdata.extend_from_slice(self.value.as_bytes());
        Rdata::new(rdata)
    }
}

#[cfg(test)]
mod tests {
    use super::CaaRecordValue;

    /// Verify that `parse` accepts quoted and bare values.
    #[test]
    fn parse_accepts_quoted_and_bare_values() {
        let quoted = CaaRecordValue::parse("0 issue \"letsencrypt.org\"").unwrap();
        assert_eq!(quoted.canonical(), "0 issue \"letsencrypt.org\"");
        let bare = CaaRecordValue::parse("0 ISSUE letsencrypt.org").unwrap();
        assert_eq!(bare.canonical(), "0 issue \"letsencrypt.org\"");
    }

    /// Verify that `parse` accepts repeated whitespace between fields.
    #[test]
    fn parse_accepts_repeated_whitespace_between_fields() {
        let spaced = CaaRecordValue::parse("  0  issue \t \"letsencrypt.org\"  ").unwrap();
        assert_eq!(spaced.canonical(), "0 issue \"letsencrypt.org\"");
    }

    /// Verify that a quoted value resolves its escapes and renders them back.
    #[test]
    fn a_quoted_value_resolves_its_escapes_and_renders_them_back() {
        // An export and a zone file both spell a quote or backslash with the
        // RFC 1035, Section 5.1 escaping.
        let parsed = CaaRecordValue::parse(r#"0 issue "a\"b\\c""#).unwrap();
        parsed.validate().unwrap();

        assert_eq!(parsed.canonical(), r#"0 issue "a\"b\\c""#);
        assert_eq!(
            parsed.to_rdata().unwrap().as_bytes(),
            b"\x00\x05issuea\"b\\c"
        );
    }

    /// Verify that `validate` rejects a bad tag or a missing value.
    #[test]
    fn validate_rejects_a_bad_tag_or_a_missing_value() {
        let long_tag = CaaRecordValue::parse("0 averyveryverylongtag x").unwrap();
        assert!(long_tag.validate().is_err());
        assert!(CaaRecordValue::parse("0 issue").is_err());
    }

    /// Verify rejection of unclosed or concatenated quoted CAA values.
    #[test]
    fn rejects_a_quoted_value_that_does_not_close_or_stand_alone() {
        for value in [r#"0 issue "unterminated"#, r#"0 issue "a" trailing"#] {
            assert!(
                CaaRecordValue::parse(value).is_err(),
                "{value} was accepted"
            );
        }
    }

    /// Verify that `validate` rejects control characters no value can spell back.
    #[test]
    fn validate_rejects_control_characters_no_value_can_spell_back() {
        let parsed = CaaRecordValue::parse("0 issue a\tb").unwrap();
        assert!(parsed.validate().is_err());
    }
}
