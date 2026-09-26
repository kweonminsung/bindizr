//! The wire RDATA a key implies: DNSKEY and its DS digests.

use base64::Engine;
use domain::base::{iana::SecurityAlgorithm, rdata::ComposeRecordData};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384};

use super::WireName;
use crate::{dns::record::Rdata, model::dnssec_key::DnssecKey};

/// The digest types `DnssecKey::ds_rdata` computes. SHA-1 only matches a parent's
/// existing DS: RFC 8624, Section 3.3 forbids it for new delegations, so
/// `ds_digest_type` never picks it.
pub const DS_DIGEST_TYPES: [u8; 3] = [1, 2, 4];

impl DnssecKey {
    /// The key's DNSKEY RDATA rebuilt from its stored public half.
    pub(crate) fn to_dnskey(&self) -> Result<domain::rdata::Dnskey<Vec<u8>>, String> {
        let public_key = base64::engine::general_purpose::STANDARD
            .decode(&self.public_key)
            .map_err(|e| format!("stored public key is not base64: {}", e))?;
        domain::rdata::Dnskey::new(
            self.role.flags(),
            3,
            SecurityAlgorithm::from_int(self.algorithm.to_int() as u8),
            public_key,
        )
        .map_err(|e| format!("stored public key is invalid: {}", e))
    }

    /// The key's DS RDATA (RFC 4034, Section 5.1.4) in `digest_type`, one of
    /// `DS_DIGEST_TYPES`; the zone publishes its algorithm's (`ds_digest_type`).
    pub fn ds_rdata(&self, apex: &WireName, digest_type: u8) -> Result<Rdata, String> {
        let dnskey = self.to_dnskey()?;
        let mut dnskey_rdata = Vec::new();
        dnskey
            .compose_rdata(&mut dnskey_rdata)
            .expect("composing into a Vec cannot run out of space");

        let digest: Vec<u8> = match digest_type {
            1 => {
                let mut hasher = Sha1::new();
                hasher.update(apex.as_slice());
                hasher.update(&dnskey_rdata);
                hasher.finalize().to_vec()
            }
            2 => {
                let mut hasher = Sha256::new();
                hasher.update(apex.as_slice());
                hasher.update(&dnskey_rdata);
                hasher.finalize().to_vec()
            }
            4 => {
                let mut hasher = Sha384::new();
                hasher.update(apex.as_slice());
                hasher.update(&dnskey_rdata);
                hasher.finalize().to_vec()
            }
            other => return Err(format!("unsupported DS digest type {}", other)),
        };

        let mut rdata = Vec::with_capacity(4 + digest.len());
        rdata.extend_from_slice(&(self.key_tag as u16).to_be_bytes());
        rdata.push(self.algorithm.to_int() as u8);
        rdata.push(digest_type);
        rdata.extend_from_slice(&digest);
        Rdata::new(rdata)
    }
}
