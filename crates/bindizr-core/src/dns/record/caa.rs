//! CAA record values (RFC 8659): which certificate authorities may issue for
//! a name.

use super::{
    Rdata,
    value::{MAX_RECORD_RDATA, parse_u8_record_field},
};

pub(crate) struct CaaRecordValue<'a> {
    flags: u8,
    tag: &'a str,
    value: &'a str,
}

impl<'a> CaaRecordValue<'a> {
    /// The value is `<flags> <tag> <value>`; the value keeps its surrounding
    /// quotes optional, as presentation form allows both. Fields may be
    /// separated by runs of whitespace, as aligned zone files spell them.
    pub(crate) fn parse(value: &'a str) -> Result<Self, String> {
        let err = || format!("CAA record value must be '<flags> <tag> <value>': {value}");
        let (flags, rest) = value
            .trim()
            .split_once(char::is_whitespace)
            .ok_or_else(err)?;
        let (tag, rest) = rest
            .trim_start()
            .split_once(char::is_whitespace)
            .ok_or_else(err)?;

        Ok(Self {
            flags: parse_u8_record_field("CAA flags", flags)?,
            tag,
            value: unquote(rest.trim()),
        })
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
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
        // These need the RFC 1035, Section 5.1 escapes the exporter never
        // emits, so a stored value carrying them breaks the import round trip.
        if self.value.contains('"') || self.value.contains('\\') {
            return Err("CAA value must not contain quotes or backslashes".to_string());
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

    pub(crate) fn canonical(&self) -> String {
        format!(
            "{} {} \"{}\"",
            self.flags,
            self.tag.to_lowercase(),
            self.value
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

/// Strip one pair of surrounding quotes; inner quotes are rejected by
/// `validate`, so no escape handling is needed.
fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::CaaRecordValue;

    #[test]
    fn parse_accepts_quoted_and_bare_values() {
        let quoted = CaaRecordValue::parse("0 issue \"letsencrypt.org\"").unwrap();
        assert_eq!(quoted.canonical(), "0 issue \"letsencrypt.org\"");
        let bare = CaaRecordValue::parse("0 ISSUE letsencrypt.org").unwrap();
        assert_eq!(bare.canonical(), "0 issue \"letsencrypt.org\"");
    }

    #[test]
    fn parse_accepts_repeated_whitespace_between_fields() {
        let spaced = CaaRecordValue::parse("  0  issue \t \"letsencrypt.org\"  ").unwrap();
        assert_eq!(spaced.canonical(), "0 issue \"letsencrypt.org\"");
    }

    #[test]
    fn validate_rejects_bad_tags_and_embedded_quotes() {
        let long_tag = CaaRecordValue::parse("0 averyveryverylongtag x").unwrap();
        assert!(long_tag.validate().is_err());
        let inner_quote = CaaRecordValue::parse("0 issue a\"b").unwrap();
        assert!(inner_quote.validate().is_err());
        assert!(CaaRecordValue::parse("0 issue").is_err());
    }

    #[test]
    fn validate_rejects_escapes_the_exporter_never_emits() {
        for value in ["0 issue a\\b", "0 issue a\tb"] {
            let parsed = CaaRecordValue::parse(value).unwrap();
            assert!(parsed.validate().is_err(), "{value} was accepted");
        }
    }
}
