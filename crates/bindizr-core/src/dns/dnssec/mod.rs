//! DNSSEC signing: key material, the RDATA it implies, and the signed view a
//! zone's records produce. Pure computation; when to sign and what to do with
//! the result is the service's.

mod signed_view;

use base64::Engine;
use chrono::{DateTime, Utc};
use domain::base::{Name, iana::SecurityAlgorithm, rdata::ComposeRecordData};
use sha2::{Digest, Sha256, Sha384};
pub use signed_view::{SignedViewDiff, SignedViewParams};

use crate::{
    dns::{name::ParseNameError, record::Rdata},
    model::{
        dnssec_key::{DnssecAlgorithm, DnssecKey, DnssecKeyRole, DnssecKeyState},
        dnssec_record::DnssecRecordType,
        zone::Zone,
    },
};

/// The name form the `domain` crate's DNSSEC machinery takes.
pub type WireName = Name<Vec<u8>>;

/// A typed name's wire bytes into the domain form.
pub fn to_wire_name(wire: Result<Vec<u8>, ParseNameError>) -> Result<WireName, String> {
    let wire = wire.map_err(|e| e.to_string())?;
    Name::from_octets(wire).map_err(|e| format!("invalid wire name: {}", e))
}

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
fn dnskey_for(key: &DnssecKey) -> Result<domain::rdata::Dnskey<Vec<u8>>, String> {
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

/// The key's DS RDATA (RFC 4034, Section 5.1.4): tag, algorithm, digest type,
/// then the digest the algorithm pairs with over the canonical apex name and
/// the DNSKEY RDATA.
pub fn ds_rdata_for(key: &DnssecKey, apex: &WireName) -> Result<Rdata, String> {
    let dnskey = dnskey_for(key)?;
    let mut dnskey_rdata = Vec::new();
    dnskey
        .compose_rdata(&mut dnskey_rdata)
        .expect("composing into a Vec cannot run out of space");

    let digest_type = key.algorithm.ds_digest_type();
    let digest: Vec<u8> = if digest_type == 4 {
        let mut hasher = Sha384::new();
        hasher.update(apex.as_slice());
        hasher.update(&dnskey_rdata);
        hasher.finalize().to_vec()
    } else {
        let mut hasher = Sha256::new();
        hasher.update(apex.as_slice());
        hasher.update(&dnskey_rdata);
        hasher.finalize().to_vec()
    };

    let mut rdata = Vec::with_capacity(4 + digest.len());
    rdata.extend_from_slice(&(key.key_tag as u16).to_be_bytes());
    rdata.push(key.algorithm.to_int() as u8);
    rdata.push(digest_type);
    rdata.extend_from_slice(&digest);
    Rdata::new(rdata)
}

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
        ds_seen_at: None,
        max_signed_ttl: 0,
        created_at: now,
    })
}

/// Rebuild a key from its BIND key files: the DNSKEY record (`K*.key`) and
/// the matching private key (`K*.private`). The pair is validated by
/// reconstructing the signer from it; the key imports as `active`.
pub fn import_key(
    zone: &Zone,
    role_override: Option<DnssecKeyRole>,
    dnskey_record: &str,
    private_key: &str,
    now: DateTime<Utc>,
) -> Result<DnssecKey, String> {
    // `K*.key` holds one DNSKEY record; the bare RDATA form is accepted too.
    let tokens: Vec<&str> = dnskey_record
        .lines()
        .filter(|line| !line.trim_start().starts_with(';'))
        .flat_map(str::split_whitespace)
        .collect();
    let rdata_at = tokens
        .iter()
        .position(|token| token.eq_ignore_ascii_case("DNSKEY"))
        .map_or(0, |index| index + 1);
    let (flags, protocol, algorithm, public) = match &tokens[rdata_at..] {
        [flags, protocol, algorithm, public @ ..] if !public.is_empty() => {
            (flags, protocol, algorithm, public.concat())
        }
        _ => return Err("DNSKEY record needs flags, protocol, algorithm, and key".to_string()),
    };

    let flags: u16 = flags
        .parse()
        .map_err(|_| format!("invalid DNSKEY flags '{}'", flags))?;
    if *protocol != "3" {
        return Err(format!("DNSKEY protocol must be 3, got '{}'", protocol));
    }
    let algorithm = algorithm
        .parse::<i32>()
        .ok()
        .and_then(DnssecAlgorithm::from_int)
        .ok_or_else(|| format!("unsupported DNSKEY algorithm '{}'", algorithm))?;
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(&public)
        .map_err(|e| format!("DNSKEY public key is not base64: {}", e))?;

    let role = match role_override {
        Some(role) => role,
        None if flags == 257 => DnssecKeyRole::Csk,
        None => DnssecKeyRole::Zsk,
    };
    if flags != role.flags() {
        return Err(format!(
            "DNSKEY flags {} do not match role {} (expected {})",
            flags,
            role,
            role.flags()
        ));
    }

    let dnskey = domain::rdata::Dnskey::new(
        flags,
        3,
        SecurityAlgorithm::from_int(algorithm.to_int() as u8),
        public_key,
    )
    .map_err(|e| format!("invalid DNSKEY: {}", e))?;
    let secret = domain::crypto::sign::SecretKeyBytes::parse_from_bind(private_key)
        .map_err(|e| format!("invalid private key: {}", e))?;
    domain::crypto::sign::KeyPair::from_bytes(&secret, &dnskey)
        .map_err(|e| format!("private key does not match the DNSKEY: {}", e))?;

    Ok(DnssecKey {
        id: 0,
        zone_id: zone.id,
        role,
        algorithm,
        key_tag: i32::from(dnskey.key_tag()),
        public_key: base64::engine::general_purpose::STANDARD.encode(dnskey.public_key()),
        private_key: secret.display_as_bind().to_string(),
        state: DnssecKeyState::Active,
        state_changed_at: now,
        eligible_at: now,
        ds_seen_at: None,
        max_signed_ttl: 0,
        created_at: now,
    })
}
