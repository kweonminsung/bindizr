//! Fresh signing-key material.

use base64::Engine;
use chrono::{DateTime, Utc};

use crate::model::{
    dnssec_key::{DnssecAlgorithm, DnssecKey, DnssecKeyRole, DnssecKeyState},
    zone::Zone,
};

/// Generate a DNSSEC key pair for the requested algorithm and role.
pub fn generate_key(
    zone: &Zone,
    algorithm: DnssecAlgorithm,
    role: DnssecKeyRole,
    state: DnssecKeyState,
    now: DateTime<Utc>,
    eligible_at: DateTime<Utc>,
) -> Result<DnssecKey, String> {
    let params = match algorithm {
        // 2048 bits is the interoperable RSA size (RFC 8624 requires >= 2048).
        DnssecAlgorithm::RsaSha256 => {
            domain::crypto::sign::GenerateParams::RsaSha256 { bits: 2048 }
        }
        DnssecAlgorithm::RsaSha512 => {
            domain::crypto::sign::GenerateParams::RsaSha512 { bits: 2048 }
        }
        DnssecAlgorithm::EcdsaP256Sha256 => domain::crypto::sign::GenerateParams::EcdsaP256Sha256,
        DnssecAlgorithm::EcdsaP384Sha384 => domain::crypto::sign::GenerateParams::EcdsaP384Sha384,
        DnssecAlgorithm::Ed25519 => domain::crypto::sign::GenerateParams::Ed25519,
        DnssecAlgorithm::Ed448 => domain::crypto::sign::GenerateParams::Ed448,
    };
    let (secret, dnskey) = domain::crypto::sign::generate(&params, role.flags())
        .map_err(|e| format!("failed to generate DNSSEC key: {}", e))?;

    Ok(DnssecKey {
        id: 0,
        zone_id: zone.id,
        role,
        algorithm,
        key_tag: i32::from(dnskey.key_tag()),
        public_key: base64::engine::general_purpose::STANDARD.encode(dnskey.public_key()),
        private_key: secret.display_as_bind().to_string(),
        state,
        state_changed_at: now,
        eligible_at,
        max_signed_ttl: 0,
        created_at: now,
    })
}
