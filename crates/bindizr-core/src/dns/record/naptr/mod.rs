mod regexp;

pub use regexp::ValidateNaptrRegexpError;
use regexp::validate_naptr_regexp;

use super::{
    EncodeRdataError, ParseRecordValueError, Rdata, to_quoted_charstr,
    value::{
        parse_char_string, parse_u16_record_field, split_record_fields,
        validate_domain_record_value,
    },
};
use crate::dns::name::{encode_name, to_fqdn};

#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub fn parse(value: &'a str) -> Result<Self, ParseRecordValueError> {
        let rest = value.trim_start();
        let (order, rest) = parse_field("NAPTR order", rest)?;
        let (preference, rest) = parse_field("NAPTR preference", rest)?;
        let (flags, rest) = parse_char_string("NAPTR flags", rest)?;
        let (services, rest) = parse_char_string("NAPTR services", rest)?;
        let (regexp, rest) = parse_char_string("NAPTR regexp", rest)?;

        let mut fields = split_record_fields(rest);
        let replacement = match (fields.next(), fields.next()) {
            (Some(replacement), None) => replacement,
            _ => {
                return Err(ParseRecordValueError::NaptrShape {
                    value: value.to_string(),
                });
            }
        };

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
    pub fn to_rdata(&self) -> Result<Rdata, EncodeRdataError> {
        let mut rdata = Vec::with_capacity(4);
        rdata.extend_from_slice(&self.order.to_be_bytes());
        rdata.extend_from_slice(&self.preference.to_be_bytes());
        for (field, text) in [
            ("NAPTR flags", &self.flags),
            ("NAPTR services", &self.services),
            ("NAPTR regexp", &self.regexp),
        ] {
            let len = u8::try_from(text.len())
                .map_err(|_| ParseRecordValueError::CharStringTooLong { field })?;
            rdata.push(len);
            rdata.extend_from_slice(text.as_bytes());
        }
        rdata.extend_from_slice(&encode_name(self.replacement)?);
        Rdata::new(rdata)
    }

    /// Validate the fields of this NAPTR value.
    pub fn validate(&self) -> Result<(), ParseRecordValueError> {
        // RFC 3403, Section 4.1: empty or ASCII alphanumeric flags.
        if !self.flags.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return Err(ParseRecordValueError::NaptrFlags);
        }
        validate_naptr_regexp(&self.regexp)?;

        // The replacement is a name or the root, which ends the rewrite chain.
        if self.replacement == "." {
            return Ok(());
        }
        // RFC 3403, Section 4.1: the two are mutually exclusive.
        if !self.regexp.is_empty() {
            return Err(ParseRecordValueError::NaptrReplacementWithRegexp);
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
            to_fqdn(self.replacement)
        )
    }

    /// A record decoded off the wire, whose character-strings are still the raw
    /// octets of RFC 3403, Section 4.1.
    pub fn from_wire(
        order: u16,
        preference: u16,
        flags: &[u8],
        services: &[u8],
        regexp: &[u8],
        replacement: &'a str,
    ) -> Result<Self, ParseRecordValueError> {
        let to_text = |field: &'static str, bytes: &[u8]| {
            std::str::from_utf8(bytes)
                .map(str::to_string)
                .map_err(|_| ParseRecordValueError::NotUtf8 { field })
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
fn parse_field<'a>(
    field: &'static str,
    input: &'a str,
) -> Result<(&'a str, &'a str), ParseRecordValueError> {
    let end = input
        .find(char::is_whitespace)
        .ok_or(ParseRecordValueError::NaptrEndsBefore { field })?;

    Ok((&input[..end], input[end..].trim_start()))
}

#[cfg(test)]
mod tests;
