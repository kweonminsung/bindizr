//! CAA record values (RFC 8659): which certificate authorities may issue for
//! a name.

use super::value::MAX_RECORD_RDATA;
use super::{EncodeRdataError, ParseRecordValueError, Rdata, value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaaRecordValue<'a> {
    flags: u8,
    tag: &'a str,
    value: Vec<u8>,
}

impl<'a> CaaRecordValue<'a> {
    /// Parse `<flags> <tag> <value>`, decoding quoted or bare value escapes.
    pub fn parse(value: &'a str) -> Result<Self, ParseRecordValueError> {
        let error = || ParseRecordValueError::CaaShape {
            value: value.to_string(),
        };
        let (flags, rest) = value
            .trim_start()
            .split_once(char::is_whitespace)
            .ok_or_else(error)?;
        let (tag, rest) = rest
            .trim_start()
            .split_once(char::is_whitespace)
            .ok_or_else(error)?;
        let rest = rest.trim_start();

        // RFC 8659, Section 4.1: property values are octets, including empty
        // or non-UTF-8 values; the presentation escapes preserve those bytes.
        let (value, trailing) = value::parse_string_octets("CAA value", rest)?;

        if !trailing.is_empty() {
            return Err(error());
        }

        Ok(Self {
            flags: value::parse_u8_record_field("CAA flags", flags)?,
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
            super::to_quoted_charstr(&self.value)
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
mod tests;
