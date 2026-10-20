//! SOA record values, including the RNAME mailbox <-> email conversions.

use std::str::{FromStr, Utf8Error};

use domain::base::{Name, name::FromStrError};
use thiserror::Error;

use crate::dns::{
    name::{encode_name, labels_to_presentation},
    record::{EncodeRdataError, Rdata},
};

/// An email that does not encode as an SOA mailbox, or a mailbox that does
/// not decode back.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseMailboxError {
    #[error("email must contain exactly one @")]
    AtCount,
    #[error(transparent)]
    Name(#[from] FromStrError),
    #[error("SOA mailbox is not UTF-8: {0}")]
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
        let mut rdata = encode_name(self.mname.as_ref())?;
        rdata.extend_from_slice(&encode_name(self.rname.as_ref())?);
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

    /// Decode mailbox labels, including decimal escapes (RFC 1035, Section 5.1).
    pub fn to_email(&self) -> Result<String, ParseMailboxError> {
        let name = Name::<Vec<u8>>::from_str(&self.0)?;
        let labels = name
            .iter()
            .filter(|label| !label.is_root())
            .map(|label| std::str::from_utf8(label.as_slice()).map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()?;
        if labels.len() < 2 {
            return Err(ParseMailboxError::NotEncodedEmail);
        }
        Ok(format!(
            "{}@{}",
            labels[0],
            labels_to_presentation(&labels[1..])
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

    for c in local.chars() {
        if c == '.' || c == '\\' {
            escaped.push('\\');
        }
        escaped.push(c);
    }

    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::name::encode_name;

    /// Verify that `from_email` escapes local part.
    #[test]
    fn from_email_escapes_local_part() {
        assert_eq!(
            SoaMailbox::from_email(r"host.master\ops@example.com")
                .unwrap()
                .as_str(),
            r"host\.master\\ops.example.com."
        );
        assert!(SoaMailbox::from_email("hostmaster.example.com").is_err());
        assert!(SoaMailbox::from_email("host@@example.com").is_err());
    }

    /// Verify that `to_email` round-trips.
    #[test]
    fn to_email_round_trips() {
        for email in [
            "admin@example.com",
            "first.last@example.com",
            "a.b.c@sub.example.com",
            "back\\slash@example.com",
        ] {
            let mailbox = SoaMailbox::from_email(email).expect("email should convert to mailbox");
            assert_eq!(
                mailbox.to_email().expect("mailbox should convert back"),
                email,
                "round trip failed for mailbox '{mailbox}'"
            );
        }
    }

    /// Verify that to email handles plain stored mailbox.
    #[test]
    fn to_email_handles_plain_stored_mailbox() {
        assert_eq!(
            SoaMailbox::from_encoded("hostmaster.example.com.")
                .to_email()
                .unwrap(),
            "hostmaster@example.com"
        );
        assert_eq!(
            SoaMailbox::from_encoded("hostmaster.example.com")
                .to_email()
                .unwrap(),
            "hostmaster@example.com"
        );
        assert_eq!(
            SoaMailbox::from_encoded(r"Host\046Master.example.com.")
                .to_email()
                .unwrap(),
            "Host.Master@example.com"
        );
    }

    /// Verify that `to_email` rejects invalid input.
    #[test]
    fn to_email_rejects_invalid_input() {
        assert!(SoaMailbox::from_encoded("no-separator").to_email().is_err());
        assert!(SoaMailbox::from_encoded(".example.com").to_email().is_err());
        assert!(SoaMailbox::from_encoded("dangling\\").to_email().is_err());
        for mailbox in [
            r"bad\99.example.com.",
            r"bad\999.example.com.",
            r"bad\255.example.com.",
        ] {
            assert!(SoaMailbox::from_encoded(mailbox).to_email().is_err());
        }
    }

    /// Verify that SOA RDATA encodes two names followed by five counters (RFC 1035, Section
    /// 3.3.13).
    #[test]
    fn encode_soa_rdata_returns_names_and_five_counters() {
        let rdata = SoaRecordValue {
            mname: "ns1.example.com",
            rname: "admin.example.com",
            serial: 42,
            refresh: 2,
            retry: 3,
            expire: 4,
            minimum: 5,
        }
        .to_rdata()
        .unwrap();
        let mut expected = encode_name("ns1.example.com").unwrap();
        expected.extend(encode_name("admin.example.com").unwrap());
        for field in [42u32, 2, 3, 4, 5] {
            expected.extend(field.to_be_bytes());
        }
        assert_eq!(rdata.as_bytes(), expected);
    }
}
