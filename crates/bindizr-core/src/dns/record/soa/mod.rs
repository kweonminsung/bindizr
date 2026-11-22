//! SOA record values, including the RNAME mailbox <-> email conversions.

use std::str::Utf8Error;
use std::{fmt, str};

use thiserror::Error;

use crate::dns::name::{EncodeNameError, ParseNameError};
use crate::dns::record::{EncodeRdataError, Rdata};
use crate::dns::{Serial, Ttl, name};

/// An email that does not encode as an SOA mailbox, or a mailbox that does
/// not decode back.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseMailboxError {
    #[error("email must contain exactly one @")]
    AtCount,
    #[error(transparent)]
    Encode(#[from] EncodeNameError),
    #[error(transparent)]
    Decode(#[from] ParseNameError),
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
    pub serial: Serial,
    /// REFRESH, RETRY and EXPIRE as the wire carries them; the service
    /// narrows them to `SoaInterval`.
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: Ttl,
}

impl<N: AsRef<str>> SoaRecordValue<N> {
    /// Encode the SOA value into wire-format record data.
    pub fn to_rdata(self) -> Result<Rdata, EncodeRdataError> {
        let mut rdata = name::encode_name(self.mname.as_ref())?;
        rdata.extend_from_slice(&name::encode_name(self.rname.as_ref())?);

        for field in [
            self.serial.as_u32(),
            self.refresh,
            self.retry,
            self.expire,
            self.minimum.as_secs(),
        ] {
            rdata.extend_from_slice(&field.to_be_bytes());
        }

        Rdata::new(rdata)
    }
}

/// An SOA RNAME mailbox in presentation form, the email local part one label
/// escaped by the name codec, so its dots stay label data.
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
            name::labels_to_presentation(&[local.as_bytes()]),
            domain.trim_end_matches('.')
        ));
        name::encode_name(mailbox.as_str())?;

        Ok(mailbox)
    }

    /// Wrap an already-encoded mailbox (e.g. a stored version value) as-is;
    /// [`Self::to_email`] validates on decode.
    pub fn from_encoded(mailbox: impl Into<String>) -> Self {
        Self(mailbox.into())
    }

    /// Decode the local part as text and escape domain octets (RFC 1035, Section 5.1).
    pub fn to_email(&self) -> Result<String, ParseMailboxError> {
        let (labels, _) = name::decode_preserved_labels(&self.0)?;

        if labels.len() < 2 {
            return Err(ParseMailboxError::NotEncodedEmail);
        }

        Ok(format!(
            "{}@{}",
            str::from_utf8(&labels[0])?,
            name::labels_to_presentation(&labels[1..])
        ))
    }

    /// Return the canonical text representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the mailbox and return its stored DNS presentation form.
    pub fn into_encoded(self) -> String {
        self.0
    }
}

impl fmt::Display for SoaMailbox {
    /// Write the SOA mailbox in its display form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests;
