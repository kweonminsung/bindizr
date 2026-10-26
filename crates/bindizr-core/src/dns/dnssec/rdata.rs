//! The wire RDATA a key implies: DNSKEY and its DS digests.

use base64::Engine;
use domain::base::iana::SecurityAlgorithm;
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384};
use thiserror::Error;

use super::WireName;
use crate::dns::LibraryError;
use crate::dns::record::{EncodeRdataError, Rdata};
use crate::model::dnssec_key::DnssecKey;

/// A stored key whose RDATA could not be rebuilt.
#[derive(Debug, Error)]
pub enum EncodeKeyRdataError {
    #[error("stored public key is not base64: {0}")]
    PublicKeyNotBase64(#[source] base64::DecodeError),
    #[error("stored public key is invalid: {0}")]
    InvalidPublicKey(#[source] LibraryError),
    #[error("unsupported DS digest type {0}")]
    UnsupportedDigestType(u8),
    #[error(transparent)]
    Rdata(#[from] EncodeRdataError),
}

/// Supported DS digests: SHA-1 only matches existing parent DS records (RFC 9905,
/// Section 5); new DS/CDS use `DS_DIGEST_TYPE`, SHA-256 (RFC 9904, Section 4).
pub const DS_DIGEST_TYPES: [u8; 3] = [1, 2, 4];

impl DnssecKey {
    /// The key's DNSKEY RDATA rebuilt from its stored public half.
    pub(crate) fn to_dnskey(&self) -> Result<domain::rdata::Dnskey<Vec<u8>>, EncodeKeyRdataError> {
        let public_key = base64::engine::general_purpose::STANDARD
            .decode(&self.public_key)
            .map_err(EncodeKeyRdataError::PublicKeyNotBase64)?;
        domain::rdata::Dnskey::new(
            self.role.flags(),
            3,
            SecurityAlgorithm::from_int(self.algorithm.as_i32() as u8),
            public_key,
        )
        .map_err(|error| EncodeKeyRdataError::InvalidPublicKey(Box::new(error)))
    }

    /// The key's DS RDATA (RFC 4034, Section 5.1.4) in `digest_type`, one of
    /// `DS_DIGEST_TYPES`; the zone publishes `DS_DIGEST_TYPE`.
    pub fn ds_rdata(&self, apex: &WireName, digest_type: u8) -> Result<Rdata, EncodeKeyRdataError> {
        use domain::base::rdata::ComposeRecordData;

        let dnskey = self.to_dnskey()?;
        let mut dnskey_rdata = Vec::new();
        let Ok(()) = dnskey.compose_rdata(&mut dnskey_rdata);

        let algorithm = match digest_type {
            1 => &SHA1_FOR_LEGACY_USE_ONLY,
            2 => &SHA256,
            4 => &SHA384,
            other => return Err(EncodeKeyRdataError::UnsupportedDigestType(other)),
        };
        let mut hasher = Context::new(algorithm);
        hasher.update(apex.as_slice());
        hasher.update(&dnskey_rdata);
        let digest = hasher.finish();

        let mut rdata = Vec::with_capacity(4 + digest.as_ref().len());
        rdata.extend_from_slice(&self.key_tag.as_u16().to_be_bytes());
        rdata.push(self.algorithm.as_i32() as u8);
        rdata.push(digest_type);
        rdata.extend_from_slice(digest.as_ref());

        Ok(Rdata::new(rdata)?)
    }
}
