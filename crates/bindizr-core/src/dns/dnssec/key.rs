//! Fresh signing-key material.

use base64::Engine;
use chrono::{DateTime, Utc};
use thiserror::Error;

use super::KeyTag;
use crate::{
    dns::{LibraryError, Ttl},
    model::{
        dnssec_key::{DnssecAlgorithm, DnssecKey, DnssecKeyId, DnssecKeyRole, DnssecKeyState},
        zone::Zone,
    },
};

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
            // 2048 bits is the interoperable RSA size (RFC 8624 requires >= 2048).
            DnssecAlgorithm::RsaSha256 => {
                domain::crypto::sign::GenerateParams::RsaSha256 { bits: 2048 }
            }
            DnssecAlgorithm::RsaSha512 => {
                domain::crypto::sign::GenerateParams::RsaSha512 { bits: 2048 }
            }
            DnssecAlgorithm::EcdsaP256Sha256 => {
                domain::crypto::sign::GenerateParams::EcdsaP256Sha256
            }
            DnssecAlgorithm::EcdsaP384Sha384 => {
                domain::crypto::sign::GenerateParams::EcdsaP384Sha384
            }
            DnssecAlgorithm::Ed25519 => domain::crypto::sign::GenerateParams::Ed25519,
            DnssecAlgorithm::Ed448 => domain::crypto::sign::GenerateParams::Ed448,
        };
        let (secret, dnskey) = domain::crypto::sign::generate(&params, role.flags())
            .map_err(|e| GenerateKeyError(Box::new(e)))?;

        Ok(DnssecKey {
            id: DnssecKeyId::UNWRITTEN,
            zone_id: zone.id,
            role,
            algorithm,
            key_tag: KeyTag::from(dnskey.key_tag()),
            public_key: base64::engine::general_purpose::STANDARD.encode(dnskey.public_key()),
            private_key: secret.display_as_bind().to_string(),
            state,
            state_changed_at: now,
            eligible_at,
            max_signed_ttl: Ttl::from_secs(0),
            created_at: now,
        })
    }
}
