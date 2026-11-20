//! The wire RDATA a key implies: DNSKEY and its DS digests.

use base64::engine::general_purpose;
use base64::{DecodeError, Engine};
use domain::base::iana::SecurityAlgorithm;
use domain::rdata::Dnskey;
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384};
use thiserror::Error;

use crate::dns::LibraryError;
use crate::dns::name::WireName;
use crate::dns::record::{DsRecordValue, EncodeRdataError, Rdata};
use crate::model::dnssec_key::DnssecKey;

/// Digest for DS/CDS generated from bindizr's keys: SHA-256, recommended by
/// the IANA registry under RFC 9904. Raw user-supplied DS records are separate.
pub const DS_DIGEST_TYPE: u8 = 2;

/// Supported DS digests: SHA-1 only matches existing parent DS records (RFC 9905,
/// Section 5); new DS/CDS use `DS_DIGEST_TYPE`, SHA-256 (RFC 9904, Section 4).
pub const DS_DIGEST_TYPES: [u8; 3] = [1, 2, 4];

/// The DNSKEY protocol field, which must be 3 (RFC 4034, Section 2.1.2).
const DNSKEY_PROTOCOL: u8 = 3;

/// A stored key whose RDATA could not be rebuilt.
#[derive(Debug, Error)]
pub enum EncodeKeyRdataError {
    #[error("stored public key is not base64: {0}")]
    PublicKeyNotBase64(#[source] DecodeError),
    #[error("stored public key is invalid: {0}")]
    InvalidPublicKey(#[source] LibraryError),
    #[error("unsupported DS digest type {digest_type}")]
    UnsupportedDigestType { digest_type: u8 },
    #[error(transparent)]
    Rdata(#[from] EncodeRdataError),
}

impl DnssecKey {
    /// Rebuild the key's DNSKEY RDATA from its stored public half.
    pub(crate) fn to_dnskey(&self) -> Result<Dnskey<Vec<u8>>, EncodeKeyRdataError> {
        let public_key = general_purpose::STANDARD
            .decode(&self.public_key)
            .map_err(EncodeKeyRdataError::PublicKeyNotBase64)?;
        Dnskey::new(
            self.role.flags(),
            DNSKEY_PROTOCOL,
            SecurityAlgorithm::from_int(self.algorithm.as_u8()),
            public_key,
        )
        .map_err(|error| EncodeKeyRdataError::InvalidPublicKey(Box::new(error)))
    }

    /// Render the key's DNSKEY RDATA in presentation form: flags, protocol,
    /// algorithm and the base64 public key (RFC 4034, Section 2.2).
    pub fn to_dnskey_presentation(&self) -> String {
        format!(
            "{} {DNSKEY_PROTOCOL} {} {}",
            self.role.flags(),
            self.algorithm.as_i32(),
            self.public_key
        )
    }

    /// Build the key's DS RDATA (RFC 4034, Section 5.1.4) in `digest_type`, one of
    /// `DS_DIGEST_TYPES`; the zone publishes `DS_DIGEST_TYPE`.
    pub fn ds_rdata(&self, apex: &WireName, digest_type: u8) -> Result<Rdata, EncodeKeyRdataError> {
        let digest = self.ds_digest(apex, digest_type)?;
        let ds = DsRecordValue::new(self.key_tag, self.algorithm.as_u8(), digest_type, digest);

        Ok(ds.to_rdata()?)
    }

    /// Return the digest a DS of this key carries in `digest_type`, one of
    /// `DS_DIGEST_TYPES` (RFC 4034, Section 5.1.4).
    pub fn ds_digest(
        &self,
        apex: &WireName,
        digest_type: u8,
    ) -> Result<Vec<u8>, EncodeKeyRdataError> {
        use domain::base::rdata::ComposeRecordData;

        let dnskey = self.to_dnskey()?;
        let mut dnskey_rdata = Vec::new();
        let Ok(()) = dnskey.compose_rdata(&mut dnskey_rdata);

        let algorithm = match digest_type {
            1 => &SHA1_FOR_LEGACY_USE_ONLY,
            2 => &SHA256,
            4 => &SHA384,
            _ => return Err(EncodeKeyRdataError::UnsupportedDigestType { digest_type }),
        };
        let mut hasher = Context::new(algorithm);
        hasher.update(apex.as_slice());
        hasher.update(&dnskey_rdata);

        Ok(hasher.finish().as_ref().to_vec())
    }
}
