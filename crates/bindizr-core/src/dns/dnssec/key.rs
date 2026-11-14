//! Fresh signing-key material.

use base64::Engine;
use base64::engine::general_purpose;
use chrono::{DateTime, Utc};
use domain::crypto::sign;
use domain::crypto::sign::GenerateParams;
use thiserror::Error;

use crate::dns::dnssec::KeyTag;
use crate::dns::{LibraryError, Ttl};
use crate::model::dnssec_key::{
    DnssecAlgorithm, DnssecKey, DnssecKeyId, DnssecKeyRole, DnssecKeyState,
};
use crate::model::zone::Zone;

/// The `domain` crate could not produce key material for the algorithm.
#[derive(Debug, Error)]
#[error("failed to generate DNSSEC key: {0}")]
pub struct GenerateKeyError(#[source] LibraryError);

impl DnssecKey {
    /// Generate a key pair for the zone with the requested algorithm and role.
    pub fn generate(
        zone: &Zone,
        algorithm: DnssecAlgorithm,
        role: DnssecKeyRole,
        state: DnssecKeyState,
        now: DateTime<Utc>,
        eligible_at: DateTime<Utc>,
    ) -> Result<Self, GenerateKeyError> {
        let params = match algorithm {
            // 2048 bits: the RSA size in common use; shorter is weak, longer
            // slows signing and swells every signed answer.
            DnssecAlgorithm::RsaSha256 => GenerateParams::RsaSha256 { bits: 2048 },
            DnssecAlgorithm::RsaSha512 => GenerateParams::RsaSha512 { bits: 2048 },
            DnssecAlgorithm::EcdsaP256Sha256 => GenerateParams::EcdsaP256Sha256,
            DnssecAlgorithm::EcdsaP384Sha384 => GenerateParams::EcdsaP384Sha384,
            DnssecAlgorithm::Ed25519 => GenerateParams::Ed25519,
            DnssecAlgorithm::Ed448 => GenerateParams::Ed448,
        };
        let (secret, dnskey) = sign::generate(&params, role.flags())
            .map_err(|error| GenerateKeyError(Box::new(error)))?;

        Ok(Self {
            id: DnssecKeyId::UNWRITTEN,
            zone_id: zone.id,
            role,
            algorithm,
            key_tag: KeyTag::from(dnskey.key_tag()),
            public_key: general_purpose::STANDARD.encode(dnskey.public_key()),
            private_key: secret.display_as_bind().to_string(),
            state,
            state_changed_at: now,
            eligible_at,
            max_signed_ttl: Ttl::from_secs(0),
            created_at: now,
        })
    }
}
