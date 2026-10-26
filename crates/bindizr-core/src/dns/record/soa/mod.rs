//! SOA record values, including the RNAME mailbox <-> email conversions.

use std::str::{FromStr, Utf8Error};

use domain::base::Name;
use domain::base::name::FromStrError;
use thiserror::Error;

use crate::dns::name;
use crate::dns::record::{EncodeRdataError, Rdata};

/// An email that does not encode as an SOA mailbox, or a mailbox that does
/// not decode back.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseMailboxError {
    #[error("email must contain exactly one @")]
    AtCount,
    #[error(transparent)]
    Name(#[from] FromStrError),
    #[error("SOA mailbox local part is not UTF-8: {0}")]
    Utf8(#[from] Utf8Error),
    #[error("SOA mailbox is not a valid encoded email")]
    NotEncodedEmail,
}

/// An SOA value as its wire fields (RFC 1035, Section 3.3.13); `rname` is the
/// mailbox presentation form, not an email address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoaRecordValue<N> {
    pub mname: N,
    pub rname: N,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

impl<N: AsRef<str>> SoaRecordValue<N> {
    /// Encode the SOA value into wire-format record data.
    pub fn to_rdata(self) -> Result<Rdata, EncodeRdataError> {
        let mut rdata = name::encode_name(self.mname.as_ref())?;
        rdata.extend_from_slice(&name::encode_name(self.rname.as_ref())?);

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
}

/// An SOA RNAME mailbox in presentation form, with the email local part's
/// dots escaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoaMailbox(String);

impl SoaMailbox {
    /// Encode an email as a mailbox, rechecking wire limits after escaping shifts label boundaries.
    /// The row form ([`Self::from_encoded`]) is already validated.
    pub fn from_email(email: &str) -> Result<Self, ParseMailboxError> {
        let (local, domain) = match email.split_once('@') {
            Some(parts) if email.matches('@').count() == 1 => parts,
            _ => return Err(ParseMailboxError::AtCount),
        };

        let mailbox = Self(format!(
            "{}.{}.",
            escape_local_part(local),
            domain.trim_end_matches('.')
        ));
        Name::<Vec<u8>>::from_str(mailbox.as_str())?;

        Ok(mailbox)
    }

    /// Wrap an already-encoded mailbox (e.g. a stored version value) as-is;
    /// [`Self::to_email`] validates on decode.
    pub fn from_encoded(mailbox: impl Into<String>) -> Self {
        Self(mailbox.into())
    }

    /// Decode the local part as text and escape domain octets (RFC 1035, Section 5.1).
    pub fn to_email(&self) -> Result<String, ParseMailboxError> {
        let name = Name::<Vec<u8>>::from_str(&self.0)?;
        let labels = name
            .iter()
            .filter(|label| !label.is_root())
            .map(domain::base::name::Label::as_slice)
            .collect::<Vec<_>>();

        if labels.len() < 2 {
            return Err(ParseMailboxError::NotEncodedEmail);
        }

        Ok(format!(
            "{}@{}",
            std::str::from_utf8(labels[0])?,
            name::labels_to_presentation(&labels[1..])
        ))
    }

    /// Return the text representation of this SOA mailbox.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the mailbox and return its stored DNS presentation form.
    pub fn into_encoded(self) -> String {
        self.0
    }
}

impl std::fmt::Display for SoaMailbox {
    /// Write the SOA mailbox in its display form.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Escape mailbox local-part characters for DNS presentation text.
fn escape_local_part(local: &str) -> String {
    let mut escaped = String::with_capacity(local.len());

    for ch in local.chars() {
        if ch == '.' || ch == '\\' {
            escaped.push('\\');
        }
        escaped.push(ch);
    }

    escaped
}

#[cfg(test)]
mod tests;
