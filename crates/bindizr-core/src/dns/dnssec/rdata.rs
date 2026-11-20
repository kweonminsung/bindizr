//! The wire RDATA a key implies: DNSKEY and its DS digests.

use base64::engine::general_purpose;
use base64::{DecodeError, Engine};
use domain::base::iana::SecurityAlgorithm;
use domain::rdata::Dnskey;
use ring::digest::{Algorithm, Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384};
use thiserror::Error;

use crate::dns::LibraryError;
use crate::dns::name::WireName;
use crate::dns::record::{DsRecordValue, EncodeRdataError, Rdata};
use crate::model::dnssec_key::DnssecKey;

/// Digest for DS/CDS generated from bindizr's keys: SHA-256, recommended by
/// the IANA registry under RFC 9904. Raw user-supplied DS records are separate.
pub const DS_DIGEST_TYPE: DsDigestType = DsDigestType::Sha256;

/// A DS digest type bindizr can compute (RFC 4034, Section 5.1.4). SHA-1 only
/// matches parent DS records already served (RFC 9905, Section 5); new DS/CDS
/// use [`DS_DIGEST_TYPE`] (RFC 9904, Section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DsDigestType {
    Sha1,
    Sha256,
    Sha384,
}

/// A DS digest type number bindizr cannot compute; a parent may still serve it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("unsupported DS digest type {digest_type}")]
pub struct ConvertDsDigestTypeError {
    pub digest_type: u8,
}

impl DsDigestType {
    /// Return the IANA digest type number, the wire octet.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Sha1 => 1,
            Self::Sha256 => 2,
            Self::Sha384 => 4,
        }
    }

    /// Return the hash this digest type names.
    fn algorithm(self) -> &'static Algorithm {
        match self {
            Self::Sha1 => &SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => &SHA256,
            Self::Sha384 => &SHA384,
        }
    }
}

impl TryFrom<u8> for DsDigestType {
    type Error = ConvertDsDigestTypeError;

    /// Read a digest type number a DS record carries.
    fn try_from(digest_type: u8) -> Result<Self, Self::Error> {
        match digest_type {
            1 => Ok(Self::Sha1),
            2 => Ok(Self::Sha256),
            4 => Ok(Self::Sha384),
            _ => Err(ConvertDsDigestTypeError { digest_type }),
        }
    }
}

/// The DNSKEY protocol field, which must be 3 (RFC 4034, Section 2.1.2).
const DNSKEY_PROTOCOL: u8 = 3;

/// A stored key whose RDATA could not be rebuilt.
#[derive(Debug, Error)]
pub enum EncodeKeyRdataError {
    #[error("stored public key is not base64: {0}")]
    PublicKeyNotBase64(#[source] DecodeError),
    #[error("stored public key is invalid: {0}")]
    InvalidPublicKey(#[source] LibraryError),
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

    /// Build the key's DS RDATA (RFC 4034, Section 5.1.4) in `digest_type`; the
    /// zone publishes [`DS_DIGEST_TYPE`].
    pub fn ds_rdata(
        &self,
        apex: &WireName,
        digest_type: DsDigestType,
    ) -> Result<Rdata, EncodeKeyRdataError> {
        let digest = self.ds_digest(apex, digest_type)?;
        let ds = DsRecordValue::new(
            self.key_tag,
            self.algorithm.as_u8(),
            digest_type.as_u8(),
            digest,
        );

        Ok(ds.to_rdata()?)
    }

    /// Return the digest a DS of this key carries in `digest_type` (RFC 4034,
    /// Section 5.1.4).
    pub fn ds_digest(
        &self,
        apex: &WireName,
        digest_type: DsDigestType,
    ) -> Result<Vec<u8>, EncodeKeyRdataError> {
        use domain::base::rdata::ComposeRecordData;

        let dnskey = self.to_dnskey()?;
        let mut dnskey_rdata = Vec::new();
        let Ok(()) = dnskey.compose_rdata(&mut dnskey_rdata);

        let mut hasher = Context::new(digest_type.algorithm());
        hasher.update(apex.as_slice());
        hasher.update(&dnskey_rdata);

        Ok(hasher.finish().as_ref().to_vec())
    }
}
