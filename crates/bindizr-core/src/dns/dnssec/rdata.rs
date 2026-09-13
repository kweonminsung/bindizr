//! The wire RDATA a key implies — DNSKEY and its DS digests — and the
//! presentation form a stored derived row prints as.

use base64::Engine;
use domain::base::{iana::SecurityAlgorithm, rdata::ComposeRecordData};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384};

use super::WireName;
use crate::{
    dns::record::Rdata,
    model::{dnssec_key::DnssecKey, dnssec_record::DnssecRecordType},
};

/// Presentation form of a derived row's wire RDATA, as `dig` prints it; the
/// base64 row form when it does not parse.
pub fn rdata_presentation(record_type: DnssecRecordType, rdata: &Rdata) -> String {
    use domain::{
        base::{iana::Rtype, name::ParsedName, rdata::ParseRecordData},
        dep::octseq::parse::Parser,
        rdata::AllRecordData,
    };

    let mut parser = Parser::from_ref(rdata.as_bytes());
    AllRecordData::<_, ParsedName<_>>::parse_rdata(
        Rtype::from_int(record_type.wire_type()),
        &mut parser,
    )
    .ok()
    .flatten()
    .filter(|_| parser.remaining() == 0)
    .map(|data| data.to_string())
    .unwrap_or_else(|| rdata.to_base64())
}

/// The key's DNSKEY RDATA rebuilt from its stored public half.
pub(crate) fn dnskey_for(key: &DnssecKey) -> Result<domain::rdata::Dnskey<Vec<u8>>, String> {
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(&key.public_key)
        .map_err(|e| format!("stored public key is not base64: {}", e))?;
    domain::rdata::Dnskey::new(
        key.role.flags(),
        3,
        SecurityAlgorithm::from_int(key.algorithm.to_int() as u8),
        public_key,
    )
    .map_err(|e| format!("stored public key is invalid: {}", e))
}

/// The digest types `ds_rdata_for` computes. SHA-1 only matches a parent's
/// existing DS: RFC 8624, Section 3.3 forbids it for new delegations, so
/// `ds_digest_type` never picks it.
pub const DS_DIGEST_TYPES: [u8; 3] = [1, 2, 4];

/// The key's DS RDATA (RFC 4034, Section 5.1.4) in `digest_type`, one of
/// `DS_DIGEST_TYPES`; the zone publishes its algorithm's (`ds_digest_type`).
pub fn ds_rdata_for(key: &DnssecKey, apex: &WireName, digest_type: u8) -> Result<Rdata, String> {
    let dnskey = dnskey_for(key)?;
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
    rdata.extend_from_slice(&(key.key_tag as u16).to_be_bytes());
    rdata.push(key.algorithm.to_int() as u8);
    rdata.push(digest_type);
    rdata.extend_from_slice(&digest);
    Rdata::new(rdata)
}
