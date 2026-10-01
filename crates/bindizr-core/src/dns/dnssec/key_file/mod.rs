//! BIND key files (`K*.key` and `K*.private`), read and written. Their timing
//! fields carry a key's place in its rollover, so a signed zone changes hands
//! without losing one.

#[cfg(test)]
mod tests;

use base64::Engine;
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use domain::base::iana::SecurityAlgorithm;

use crate::{
    dns::{LibraryError, Ttl, dnssec::KeyTag},
    model::{
        dnssec_key::{DnssecAlgorithm, DnssecKey, DnssecKeyId, DnssecKeyRole, DnssecKeyState},
        zone::Zone,
    },
};

/// A BIND key pair bindizr cannot take over as it stands.
#[derive(Debug, Error)]
pub enum ImportKeyError {
    #[error("invalid {field} time '{value}' in the private key file")]
    InvalidTime { field: String, value: String },
    #[error("this key's Delete time ({at}) has passed, so BIND no longer serves it")]
    Deleted { at: String },
    #[error("this key is not published until {at}, so BIND does not serve it yet")]
    NotYetPublished { at: String },
    #[error("DNSKEY record needs flags, protocol, algorithm, and key")]
    DnskeyShape,
    #[error("invalid DNSKEY flags '{value}'")]
    Flags { value: String },
    #[error("DNSKEY protocol must be 3, got '{value}'")]
    Protocol { value: String },
    #[error("unsupported DNSKEY algorithm '{value}'")]
    Algorithm { value: String },
    #[error("DNSKEY public key is not base64: {0}")]
    PublicKeyNotBase64(#[source] base64::DecodeError),
    #[error("a 256-flag key is a ZSK, which a single-CSK layout does not use")]
    ZskInCskLayout,
    #[error("unsupported DNSKEY flags {flags} (expected 256 or 257)")]
    UnsupportedFlags { flags: u16 },
    #[error("invalid DNSKEY: {0}")]
    Dnskey(#[source] LibraryError),
    #[error("invalid private key: {0}")]
    PrivateKey(#[source] LibraryError),
    #[error("private key does not match the DNSKEY: {0}")]
    KeyMismatch(#[source] LibraryError),
}
use thiserror::Error;

impl DnssecKey {
    /// The key's `K*.private` contents: the stored key material, plus the timing
    /// fields BIND and [`DnssecKey::import`] read a rollover from, so an export
    /// re-imports where it left off.
    pub fn to_bind_private_file(&self) -> String {
        let timing = match self.state {
            DnssecKeyState::Published => vec![
                ("Publish", self.state_changed_at),
                ("Activate", self.eligible_at),
            ],
            DnssecKeyState::Active => vec![
                ("Publish", self.created_at),
                ("Activate", self.state_changed_at),
            ],
            // The original activation is not kept; creation stands in for it,
            // since only Inactive and Delete decide a retired key's fate.
            DnssecKeyState::Retired => vec![
                ("Publish", self.created_at),
                ("Activate", self.created_at),
                ("Inactive", self.state_changed_at),
                ("Delete", self.eligible_at),
            ],
        };

        let mut file = self.private_key.trim_end().to_string();
        for (field, at) in [("Created", self.created_at)].into_iter().chain(timing) {
            file.push_str(&format!("\n{}: {}", field, at.format("%Y%m%d%H%M%S")));
        }
        file.push('\n');
        file
    }
}

/// One of BIND's key timing fields from a `K*.private` file, written by
/// `dnssec-keygen` and `dnssec-settime` as UTC `YYYYMMDDHHMMSS`.
fn parse_bind_key_time(
    private_key: &str,
    field: &str,
) -> Result<Option<DateTime<Utc>>, ImportKeyError> {
    let Some(value) = private_key.lines().find_map(|line| {
        line.split_once(':')
            .filter(|(name, _)| name.trim() == field)
            .map(|(_, value)| value.trim())
    }) else {
        return Ok(None);
    };
    NaiveDateTime::parse_from_str(value, "%Y%m%d%H%M%S")
        .map(|time| Some(time.and_utc()))
        .map_err(|_| ImportKeyError::InvalidTime {
            field: field.to_string(),
            value: value.to_string(),
        })
}

/// Where an imported key stands in its rollover: the state it is in, when it
/// entered it, and when it may move on.
struct DnssecKeyPhase {
    state: DnssecKeyState,
    state_changed_at: DateTime<Utc>,
    eligible_at: DateTime<Utc>,
}

/// Place an imported key in its rollover from BIND's timing metadata. A file
/// carrying no timing is a settled active key.
fn bind_key_phase(
    private_key: &str,
    default_ttl: Ttl,
    now: DateTime<Utc>,
) -> Result<DnssecKeyPhase, ImportKeyError> {
    let time = |field| parse_bind_key_time(private_key, field);
    let (publish, activate, inactive, delete) = (
        time("Publish")?,
        time("Activate")?,
        time("Inactive")?,
        time("Delete")?,
    );
    let passed = |at: Option<DateTime<Utc>>| at.filter(|at| *at <= now);

    if let Some(delete) = passed(delete) {
        return Err(ImportKeyError::Deleted {
            at: delete.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        });
    }
    // The DNSKEY record set's own TTL bounds how long a resolver can hold an answer
    // that lacks this key, or holds it; a recorded schedule is exact and wins.
    let ttl_wait = Duration::seconds(i64::from(default_ttl.as_secs()));
    if let Some(inactive) = passed(inactive) {
        // Its signatures outlive it in caches for the TTL of the record sets it
        // signed, which a zone signed elsewhere never told bindizr.
        return Ok(DnssecKeyPhase {
            state: DnssecKeyState::Retired,
            state_changed_at: inactive,
            eligible_at: delete.unwrap_or(now + ttl_wait),
        });
    }
    if let Some(activate) = passed(activate) {
        return Ok(DnssecKeyPhase {
            state: DnssecKeyState::Active,
            state_changed_at: activate,
            eligible_at: activate,
        });
    }
    if let Some(publish) = passed(publish) {
        return Ok(DnssecKeyPhase {
            state: DnssecKeyState::Published,
            state_changed_at: publish,
            eligible_at: activate.unwrap_or(now + ttl_wait),
        });
    }
    match publish.or(activate) {
        Some(at) => Err(ImportKeyError::NotYetPublished {
            at: at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        }),
        None => Ok(DnssecKeyPhase {
            state: DnssecKeyState::Active,
            state_changed_at: now,
            eligible_at: now,
        }),
    }
}

impl DnssecKey {
    /// Rebuild and validate a signer from its BIND key pair, using the zone's
    /// key layout for its role and the private file's timing for its rollover state.
    pub fn import(
        zone: &Zone,
        split_keys: bool,
        dnskey_record: &str,
        private_key: &str,
        now: DateTime<Utc>,
    ) -> Result<Self, ImportKeyError> {
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
            _ => return Err(ImportKeyError::DnskeyShape),
        };

        let flags: u16 = flags.parse().map_err(|_| ImportKeyError::Flags {
            value: flags.to_string(),
        })?;
        if *protocol != "3" {
            return Err(ImportKeyError::Protocol {
                value: protocol.to_string(),
            });
        }
        let algorithm = algorithm
            .parse::<i32>()
            .ok()
            .and_then(DnssecAlgorithm::from_int)
            .ok_or_else(|| ImportKeyError::Algorithm {
                value: algorithm.to_string(),
            })?;
        let public_key = base64::engine::general_purpose::STANDARD
            .decode(&public)
            .map_err(ImportKeyError::PublicKeyNotBase64)?;

        // Interpret the SEP flag using the zone's CSK or split-key layout.
        let role = match (flags, split_keys) {
            (257, false) => DnssecKeyRole::Csk,
            (257, true) => DnssecKeyRole::Ksk,
            (256, true) => DnssecKeyRole::Zsk,
            (256, false) => return Err(ImportKeyError::ZskInCskLayout),
            _ => return Err(ImportKeyError::UnsupportedFlags { flags }),
        };

        // Reconstruct the pair to reject a private key for a different DNSKEY.
        let dnskey = domain::rdata::Dnskey::new(
            flags,
            3,
            SecurityAlgorithm::from_int(algorithm.to_int() as u8),
            public_key,
        )
        .map_err(|e| ImportKeyError::Dnskey(Box::new(e)))?;
        let secret = domain::crypto::sign::SecretKeyBytes::parse_from_bind(private_key)
            .map_err(|e| ImportKeyError::PrivateKey(Box::new(e)))?;
        domain::crypto::sign::KeyPair::from_bytes(&secret, &dnskey)
            .map_err(|e| ImportKeyError::KeyMismatch(Box::new(e)))?;

        // Preserve the rollover phase encoded by the private file's timing fields.
        let DnssecKeyPhase {
            state,
            state_changed_at,
            eligible_at,
        } = bind_key_phase(private_key, zone.default_ttl, now)?;

        Ok(DnssecKey {
            id: DnssecKeyId::UNWRITTEN,
            zone_id: zone.id,
            role,
            algorithm,
            key_tag: KeyTag::from(dnskey.key_tag()),
            public_key: base64::engine::general_purpose::STANDARD.encode(dnskey.public_key()),
            private_key: secret.display_as_bind().to_string(),
            state,
            state_changed_at,
            eligible_at,
            max_signed_ttl: Ttl::from_secs(0),
            created_at: now,
        })
    }
}
