//! CAA record values (RFC 8659): which certificate authorities may issue for
//! a name.

use super::{
    EncodeRdataError, ParseRecordValueError, Rdata, to_quoted_charstr,
    value::{MAX_RECORD_RDATA, parse_string_octets, parse_u8_record_field},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaaRecordValue<'a> {
    flags: u8,
    tag: &'a str,
    value: Vec<u8>,
}

impl<'a> CaaRecordValue<'a> {
    /// Parse `<flags> <tag> <value>`, decoding quoted or bare value escapes.
    pub fn parse(value: &'a str) -> Result<Self, ParseRecordValueError> {
        let err = || ParseRecordValueError::CaaShape {
            value: value.to_string(),
        };
        let (flags, rest) = value
            .trim_start()
            .split_once(char::is_whitespace)
            .ok_or_else(err)?;
        let (tag, rest) = rest
            .trim_start()
            .split_once(char::is_whitespace)
            .ok_or_else(err)?;
        let rest = rest.trim_start();

        // RFC 8659, Section 4.1: property values are octets, including empty
        // or non-UTF-8 values; the presentation escapes preserve those bytes.
        let (value, trailing) = parse_string_octets("CAA value", rest)?;
        if !trailing.is_empty() {
            return Err(err());
        }

        Ok(Self {
            flags: parse_u8_record_field("CAA flags", flags)?,
            tag,
            value,
        })
    }

    /// Validate the fields of this CAA value.
    pub fn validate(&self) -> Result<(), ParseRecordValueError> {
        // RFC 8659, Section 4.1: a nonempty ASCII tag has a one-octet length.
        if self.tag.is_empty()
            || self.tag.len() > usize::from(u8::MAX)
            || !self.tag.chars().all(|c| c.is_ascii_alphanumeric())
        {
            return Err(ParseRecordValueError::CaaTag {
                tag: self.tag.to_string(),
            });
        }
        // Bounded so the record fits one transfer message beside the flags and
        // length-prefixed tag; enforced here so a stored row cannot poison an AXFR.
        let max_value = MAX_RECORD_RDATA - 2 - self.tag.len();
        if self.value.len() > max_value {
            return Err(ParseRecordValueError::CaaValueTooLong {
                max: max_value,
                len: self.value.len(),
            });
        }
        Ok(())
    }

    /// Validate authored flags under RFC 8659, Section 4.1;
    /// received records preserve unknown flag bits.
    pub fn validate_creation(&self) -> Result<(), ParseRecordValueError> {
        self.validate()?;
        if self.flags & 0x7f != 0 {
            return Err(ParseRecordValueError::CaaReservedFlags);
        }
        Ok(())
    }

    /// Render the CAA value in canonical text form.
    pub fn canonical(&self) -> String {
        format!(
            "{} {} {}",
            self.flags,
            self.tag,
            to_quoted_charstr(&self.value)
        )
    }

    /// Encode the stored value as wire RDATA (RFC 8659, Section 4.1).
    pub fn to_rdata(&self) -> Result<Rdata, EncodeRdataError> {
        let tag_len = u8::try_from(self.tag.len()).map_err(|_| ParseRecordValueError::CaaTag {
            tag: self.tag.to_string(),
        })?;
        let mut rdata = Vec::with_capacity(2 + self.tag.len() + self.value.len());
        rdata.push(self.flags);
        rdata.push(tag_len);
        rdata.extend_from_slice(self.tag.as_bytes());
        rdata.extend_from_slice(&self.value);
        Rdata::new(rdata)
    }
}

#[cfg(test)]
mod tests {
    use super::CaaRecordValue;

    /// Preserve empty CAA properties, including the no-issuer form in RFC 8659, Section 4.2.
    #[test]
    fn caa_encoding_preserves_empty_properties() {
        for tag in ["issue", "issuewild", "unknown"] {
            let text = format!("0 {tag} \"\"");
            let parsed = CaaRecordValue::parse(&text).unwrap();
            parsed.validate().unwrap();
            assert_eq!(parsed.canonical(), text);
            let mut expected = vec![0, u8::try_from(tag.len()).unwrap()];
            expected.extend_from_slice(tag.as_bytes());
            assert_eq!(parsed.to_rdata().unwrap().as_bytes(), expected);
        }
    }

    /// Verify that `parse` accepts quoted and bare values.
    #[test]
    fn parse_accepts_quoted_and_bare_values() {
        let quoted = CaaRecordValue::parse("0 issue \"letsencrypt.org\"").unwrap();
        assert_eq!(quoted.canonical(), "0 issue \"letsencrypt.org\"");
        let bare = CaaRecordValue::parse("0 ISSUE letsencrypt.org").unwrap();
        assert_eq!(bare.canonical(), "0 ISSUE \"letsencrypt.org\"");
    }

    /// Verify that `parse` accepts repeated whitespace between fields.
    #[test]
    fn parse_accepts_repeated_whitespace_between_fields() {
        let spaced = CaaRecordValue::parse("  0  issue \t \"letsencrypt.org\"  ").unwrap();
        assert_eq!(spaced.canonical(), "0 issue \"letsencrypt.org\"");
    }

    /// Verify that a quoted value resolves its escapes and renders them back.
    #[test]
    fn caa_parse_round_trips_quoted_value_escapes() {
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

    /// Reject malformed tags and distinguish a missing value from an empty one.
    #[test]
    fn validate_rejects_a_bad_tag_or_a_missing_value() {
        for tag in ["a".repeat(256), "bad-tag".to_string(), "é".to_string()] {
            let text = format!("0 {tag} \"\"");
            assert!(CaaRecordValue::parse(&text).unwrap().validate().is_err());
        }
        for text in ["0 issue", "0 issue   ", "0  \"\""] {
            assert!(CaaRecordValue::parse(text).is_err());
        }
    }

    /// Verify rejection of unclosed or concatenated quoted CAA values.
    #[test]
    fn caa_parse_rejects_unclosed_or_concatenated_quoted_values() {
        for value in [r#"0 issue "unterminated"#, r#"0 issue "a" trailing"#] {
            assert!(
                CaaRecordValue::parse(value).is_err(),
                "{value} was accepted"
            );
        }
    }

    /// Require quotes or escapes for whitespace within a CAA value.
    #[test]
    fn caa_parse_splits_fields_at_unquoted_whitespace() {
        for text in ["0 issue a\tb", "0 issue a b", "0 issue a\"b"] {
            assert!(CaaRecordValue::parse(text).is_err());
        }
        for text in [r"0 issue a\032b", r"0 issue a\ b", r#"0 issue "a b""#] {
            let parsed = CaaRecordValue::parse(text).unwrap();
            parsed.validate().unwrap();
            assert_eq!(parsed.canonical(), r#"0 issue "a b""#);
        }
        let trailing_space = CaaRecordValue::parse("0 issue a\\ ").unwrap();
        assert_eq!(trailing_space.canonical(), r#"0 issue "a ""#);
    }

    /// Preserve every property octet through presentation and wire encoding.
    #[test]
    fn property_values_preserve_all_octets() {
        let escaped: String = (0..=255u8).map(|byte| format!("\\{byte:03}")).collect();
        for text in [
            format!("128 custom {escaped}"),
            format!("128 custom \"{escaped}\""),
        ] {
            let parsed = CaaRecordValue::parse(&text).unwrap();
            parsed.validate().unwrap();
            let mut expected = b"\x80\x06custom".to_vec();
            expected.extend(0..=255u8);
            assert_eq!(parsed.to_rdata().unwrap().as_bytes(), expected);
            let canonical = parsed.canonical();
            let reparsed = CaaRecordValue::parse(&canonical).unwrap();
            assert_eq!(reparsed.to_rdata().unwrap().as_bytes(), expected);
        }
        for text in [
            r"0 issue \1",
            r"0 issue \12",
            r"0 issue \256",
            "0 issue x\\",
        ] {
            assert!(CaaRecordValue::parse(text).is_err(), "{text}");
        }
    }

    /// Bound the decoded RDATA, including a full-length tag and a value over 255 bytes.
    #[test]
    fn caa_validation_enforces_wire_field_lengths() {
        use super::super::{ParseRecordValueError, value::MAX_RECORD_RDATA};

        for tag_len in [1, 15, 16, 255] {
            let tag = "a".repeat(tag_len);
            let max = MAX_RECORD_RDATA - 2 - tag_len;
            let text = format!("0 {tag} \"{}\"", r"\255".repeat(max));
            let parsed = CaaRecordValue::parse(&text).unwrap();
            parsed.validate().unwrap();
            let rdata = parsed.to_rdata().unwrap();
            assert_eq!(rdata.as_bytes().len(), MAX_RECORD_RDATA);
            assert_eq!(usize::from(rdata.as_bytes()[1]), tag_len);

            let oversized = format!("0 {tag} \"{}\"", r"\255".repeat(max + 1));
            assert!(matches!(
                CaaRecordValue::parse(&oversized).unwrap().validate(),
                Err(ParseRecordValueError::CaaValueTooLong { .. })
            ));
        }
    }
}
