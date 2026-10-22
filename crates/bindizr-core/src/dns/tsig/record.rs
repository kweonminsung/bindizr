//! Validate TSIG placement and authenticate its original wire variables.

use domain::{
    base::{Message, Record, Rtype, ToName, iana::Class, name::ParsedName},
    rdata::tsig::Tsig,
};
use ring::hmac;
use subtle::ConstantTimeEq;
use thiserror::Error;

use super::TsigSigningKey;
use crate::dns::{LibraryError, message::DNS_HEADER_LEN};

type WireTsig<'a> = Record<ParsedName<&'a [u8]>, Tsig<&'a [u8], ParsedName<&'a [u8]>>>;

/// The final Additional record and where the signed DNS message ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ParsedTsig<'a> {
    pub(super) record: WireTsig<'a>,
    start: usize,
}

/// A malformed TSIG record or its enclosing DNS sections.
#[derive(Debug, Error)]
pub(super) enum ParseTsigError {
    #[error("failed to read TSIG record: {0}")]
    Read(#[source] LibraryError),
    #[error("invalid TSIG position, class or TTL")]
    Shape,
}

/// The received MAC cannot match the complete digest or its permitted prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(super) enum VerifyMacError {
    #[error("TSIG MAC exceeds the digest length")]
    Length,
    #[error("TSIG MAC does not match")]
    Mismatch,
}

impl<'a> ParsedTsig<'a> {
    /// Require one final TSIG with CLASS ANY and TTL zero (RFC 8945, Sections 4.2 and 5.2).
    pub(super) fn parse(message: &Message<&'a [u8]>) -> Result<Option<Self>, ParseTsigError> {
        for section in [message.answer(), message.authority()] {
            for record in section.map_err(|error| ParseTsigError::Read(Box::new(error)))? {
                if record
                    .map_err(|error| ParseTsigError::Read(Box::new(error)))?
                    .rtype()
                    == Rtype::TSIG
                {
                    return Err(ParseTsigError::Shape);
                }
            }
        }

        let mut section = message
            .additional()
            .map_err(|error| ParseTsigError::Read(Box::new(error)))?;

        loop {
            let start = section.pos();
            let Some(record) = section.next() else {
                return Ok(None);
            };
            let record = record.map_err(|error| ParseTsigError::Read(Box::new(error)))?;

            if record.rtype() != Rtype::TSIG {
                continue;
            }
            if section.next().is_some()
                || section.pos() != message.as_slice().len()
                || record.class() != Class::ANY
                || record.ttl().as_secs() != 0
            {
                return Err(ParseTsigError::Shape);
            }

            let record = record
                .into_record::<Tsig<_, _>>()
                .map_err(|error| ParseTsigError::Read(Box::new(error)))?
                .ok_or(ParseTsigError::Shape)?;

            return Ok(Some(Self { record, start }));
        }
    }

    /// Compare the key name and algorithm without changing signed message octets.
    pub(super) fn matches_key(&self, key: &TsigSigningKey) -> bool {
        self.record.owner().name_eq(key.domain.name())
            && self
                .record
                .data()
                .algorithm()
                .name_eq(&key.domain.algorithm().to_name())
    }

    /// Authenticate Other Len and Other Data exactly as sent (RFC 8945, Section 4.3.3).
    pub(super) fn verify_mac(
        &self,
        key: &TsigSigningKey,
        message: &Message<&[u8]>,
        request_mac: Option<&[u8]>,
    ) -> Result<(), VerifyMacError> {
        let data = self.record.data();
        let mut digest = hmac::Context::with_key(&key.hmac);

        if let Some(mac) = request_mac {
            digest.update(&(mac.len() as u16).to_be_bytes());
            digest.update(mac);
        }

        let mut header = message.header_section();
        header.header_mut().set_id(data.original_id());
        header.counts_mut().dec_arcount();
        digest.update(header.as_slice());
        digest.update(&message.as_slice()[DNS_HEADER_LEN..self.start]);
        let name = self.record.owner().to_canonical_name::<Vec<u8>>();
        let algorithm = data.algorithm().to_canonical_name::<Vec<u8>>();
        digest.update(name.as_slice());
        digest.update(&Class::ANY.to_int().to_be_bytes());
        digest.update(&0u32.to_be_bytes());
        digest.update(algorithm.as_slice());
        digest.update(&data.time_signed().into_octets());
        digest.update(&data.fudge().to_be_bytes());
        digest.update(&data.error().to_int().to_be_bytes());
        digest.update(&(data.other().len() as u16).to_be_bytes());
        digest.update(data.other());
        let expected = digest.sign();
        let Some(expected) = expected.as_ref().get(..data.mac().len()) else {
            return Err(VerifyMacError::Length);
        };

        if expected.ct_eq(data.mac()).into() {
            Ok(())
        } else {
            Err(VerifyMacError::Mismatch)
        }
    }
}
