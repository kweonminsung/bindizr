//! The wire RDATA a key implies: DNSKEY and its DS digests.

use base64::Engine;
use domain::base::{iana::SecurityAlgorithm, rdata::ComposeRecordData};
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384};
use thiserror::Error;

use super::WireName;
use crate::{
    dns::{
        LibraryError,
        record::{EncodeRdataError, Rdata},
    },
    model::dnssec_key::DnssecKey,
};

/// A stored key whose RDATA could not be rebuilt.
#[derive(Debug, Error)]
pub enum KeyRdataError {
    #[error("stored public key is not base64: {0}")]
    PublicKeyNotBase64(#[source] base64::DecodeError),
    #[error("stored public key is invalid: {0}")]
    InvalidPublicKey(#[source] LibraryError),
    #[error("unsupported DS digest type {0}")]
    UnsupportedDigestType(u8),
    #[error(transparent)]
    Rdata(#[from] EncodeRdataError),
}

/// The digest types `DnssecKey::ds_rdata` computes. SHA-1 only matches a parent's
/// existing DS: RFC 8624, Section 3.3 forbids it for new delegations, so
/// `ds_digest_type` never picks it.
pub const DS_DIGEST_TYPES: [u8; 3] = [1, 2, 4];

impl DnssecKey {
    /// The key's DNSKEY RDATA rebuilt from its stored public half.
    pub(crate) fn to_dnskey(&self) -> Result<domain::rdata::Dnskey<Vec<u8>>, KeyRdataError> {
        let public_key = base64::engine::general_purpose::STANDARD
            .decode(&self.public_key)
            .map_err(KeyRdataError::PublicKeyNotBase64)?;
        domain::rdata::Dnskey::new(
            self.role.flags(),
            3,
            SecurityAlgorithm::from_int(self.algorithm.to_int() as u8),
            public_key,
        )
        .map_err(|e| KeyRdataError::InvalidPublicKey(Box::new(e)))
    }

    /// The key's DS RDATA (RFC 4034, Section 5.1.4) in `digest_type`, one of
    /// `DS_DIGEST_TYPES`; the zone publishes its algorithm's (`ds_digest_type`).
    pub fn ds_rdata(&self, apex: &WireName, digest_type: u8) -> Result<Rdata, KeyRdataError> {
        let dnskey = self.to_dnskey()?;
        let mut dnskey_rdata = Vec::new();
        let Ok(()) = dnskey.compose_rdata(&mut dnskey_rdata);

        let algorithm = match digest_type {
            1 => &SHA1_FOR_LEGACY_USE_ONLY,
            2 => &SHA256,
            4 => &SHA384,
            other => return Err(KeyRdataError::UnsupportedDigestType(other)),
        };
        let mut hasher = Context::new(algorithm);
        hasher.update(apex.as_slice());
        hasher.update(&dnskey_rdata);
        let digest = hasher.finish();

        let mut rdata = Vec::with_capacity(4 + digest.as_ref().len());
        rdata.extend_from_slice(&self.key_tag.as_u16().to_be_bytes());
        rdata.push(self.algorithm.to_int() as u8);
        rdata.push(digest_type);
        rdata.extend_from_slice(digest.as_ref());
        Ok(Rdata::new(rdata)?)
    }
}
