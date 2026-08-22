//! SOA record values, including the RNAME mailbox <-> email conversions.

use super::value::{parse_u32_record_field, validate_domain_record_value};
use crate::dns::{
    name::{MAX_DNS_LABEL_LEN, MAX_DOMAIN_LEN, ParseNameError, encode_name, to_fqdn_lowercase},
    record::Rdata,
};

/// An SOA value as its wire fields (RFC 1035, Section 3.3.13); `rname` is the
/// mailbox presentation form, not an email address.
pub struct SoaRecordValue<'a> {
    pub mname: &'a str,
    pub rname: &'a str,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

impl<'a> SoaRecordValue<'a> {
    pub(crate) fn parse(value: &'a str) -> Result<Self, String> {
        // The trailing `None` rejects a value with more than seven fields.
        let mut fields = value.split_whitespace();
        match (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) {
            (
                Some(mname),
                Some(rname),
                Some(serial),
                Some(refresh),
                Some(retry),
                Some(expire),
                Some(minimum),
                None,
            ) => Ok(Self {
                mname,
                rname,
                serial: parse_u32_record_field("SOA serial", serial)?,
                refresh: parse_u32_record_field("SOA refresh", refresh)?,
                retry: parse_u32_record_field("SOA retry", retry)?,
                expire: parse_u32_record_field("SOA expire", expire)?,
                minimum: parse_u32_record_field("SOA minimum", minimum)?,
            }),
            _ => Err(format!(
                "SOA record value must be '<mname> <rname> <serial> <refresh> <retry> <expire> <minimum>': {value}"
            )),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        validate_domain_record_value("SOA mname", self.mname)?;
        validate_domain_record_value("SOA rname", self.rname)?;
        Ok(())
    }

    /// The wire-format RDATA of this SOA value.
    pub fn to_rdata(&self) -> Result<Rdata, String> {
        let mut rdata = encode_name(self.mname)?;
        rdata.extend_from_slice(&encode_name(self.rname)?);
        for field in [
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum,
        ] {
            rdata.extend_from_slice(&field.to_be_bytes());
        }
        Rdata::new(rdata)
    }

    pub(crate) fn canonical(&self) -> String {
        format!(
            "{} {} {} {} {} {} {}",
            to_fqdn_lowercase(self.mname),
            to_fqdn_lowercase(self.rname),
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum,
        )
    }
}

/// An SOA RNAME mailbox in presentation form, with the email local part's
/// dots escaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoaMailbox(String);

impl SoaMailbox {
    /// Encode an email address into mailbox form. Escaping the local part can
    /// shift label boundaries past the wire limits, so they are re-checked
    /// here; the row form ([`Self::from_encoded`]) is trusted.
    pub fn from_email(email: &str) -> Result<Self, String> {
        let (local, domain) = match email.split_once('@') {
            Some(parts) if email.matches('@').count() == 1 => parts,
            _ => return Err("email must contain exactly one @".to_string()),
        };

        let mailbox = Self(format!(
            "{}.{}.",
            escape_local_part(local),
            domain.trim_end_matches('.')
        ));
        mailbox.classify_wire_labels().map_err(|e| e.to_string())?;
        Ok(mailbox)
    }

    /// Wrap an already-encoded mailbox (e.g. a stored version value) as-is;
    /// [`Self::to_email`] validates on decode.
    pub fn from_encoded(mailbox: impl Into<String>) -> Self {
        Self(mailbox.into())
    }

    /// Decode back into an email address. The first unescaped '.' separates
    /// the local part from the domain; `\.` and `\\` are unescaped.
    pub fn to_email(&self) -> Result<String, String> {
        let mailbox = self.0.trim_end_matches('.');
        let mut local = String::with_capacity(mailbox.len());
        let mut chars = mailbox.chars();

        while let Some(c) = chars.next() {
            match c {
                '\\' => match chars.next() {
                    Some(escaped) => local.push(escaped),
                    None => return Err("SOA mailbox contains a dangling escape".to_string()),
                },
                '.' => {
                    let domain: String = chars.collect();
                    if local.is_empty() || domain.is_empty() {
                        return Err("SOA mailbox is not a valid encoded email".to_string());
                    }
                    return Ok(format!("{}@{}", local, domain));
                }
                c => local.push(c),
            }
        }

        Err("SOA mailbox is not a valid encoded email".to_string())
    }

    fn classify_wire_labels(&self) -> Result<(), ParseNameError> {
        let bare = self.0.trim_end_matches('.');
        if bare.len() > MAX_DOMAIN_LEN {
            return Err(ParseNameError::TooLong);
        }

        for label in decode_labels(bare)? {
            if label.is_empty() {
                return Err(ParseNameError::EmptyLabel);
            }
            if label.len() > MAX_DNS_LABEL_LEN {
                return Err(ParseNameError::LabelTooLong);
            }
        }

        Ok(())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_encoded(self) -> String {
        self.0
    }
}

/// Split a mailbox into its decoded labels, so the local part's escaped dots
/// stay inside one label (RFC 1035, Section 5.1).
fn decode_labels(mailbox: &str) -> Result<Vec<String>, ParseNameError> {
    let mut labels = Vec::new();
    let mut label = String::new();
    let mut chars = mailbox.chars();

    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(escaped) => label.push(escaped),
                None => return Err(ParseNameError::DanglingEscape),
            },
            '.' => labels.push(std::mem::take(&mut label)),
            c => label.push(c),
        }
    }

    labels.push(label);
    Ok(labels)
}

impl std::fmt::Display for SoaMailbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn escape_local_part(local: &str) -> String {
    let mut escaped = String::with_capacity(local.len());

    for c in local.chars() {
        if c == '.' || c == '\\' {
            escaped.push('\\');
        }
        escaped.push(c);
    }

    escaped
}

#[cfg(test)]
mod tests;
