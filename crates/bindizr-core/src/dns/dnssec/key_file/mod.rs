//! BIND key files (`K*.key` and `K*.private`), read and written. Their timing
//! fields carry a key's place in its rollover, so a signed zone changes hands
//! without losing one.

#[cfg(test)]
mod tests;

use base64::Engine;
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use domain::base::iana::SecurityAlgorithm;

use crate::model::{
    dnssec_key::{DnssecAlgorithm, DnssecKey, DnssecKeyRole, DnssecKeyState},
    zone::Zone,
};

impl DnssecKey {
    /// The key's `K*.private` contents: the stored key material, plus the timing
    /// fields BIND and [`import_key`] read a rollover from, so an export
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
fn parse_bind_key_time(private_key: &str, field: &str) -> Result<Option<DateTime<Utc>>, String> {
    let Some(value) = private_key.lines().find_map(|line| {
        line.split_once(':')
            .filter(|(name, _)| name.trim() == field)
            .map(|(_, value)| value.trim())
    }) else {
        return Ok(None);
    };
    NaiveDateTime::parse_from_str(value, "%Y%m%d%H%M%S")
        .map(|time| Some(time.and_utc()))
        .map_err(|_| format!("invalid {} time '{}' in the private key file", field, value))
}

/// Place an imported key in its rollover from BIND's timing metadata: the
/// state it is in, when it entered it, and when it may move on. A file
/// carrying no timing is a settled active key.
fn bind_key_phase(
    private_key: &str,
    default_ttl: i32,
    now: DateTime<Utc>,
) -> Result<(DnssecKeyState, DateTime<Utc>, DateTime<Utc>), String> {
    let time = |field| parse_bind_key_time(private_key, field);
    let (publish, activate, inactive, delete) = (
        time("Publish")?,
        time("Activate")?,
        time("Inactive")?,
        time("Delete")?,
    );
    let passed = |at: Option<DateTime<Utc>>| at.filter(|at| *at <= now);

    if let Some(delete) = passed(delete) {
        return Err(format!(
            "this key's Delete time ({}) has passed, so BIND no longer serves it",
            delete.format("%Y-%m-%dT%H:%M:%SZ")
        ));
    }
    // The DNSKEY RRset's own TTL bounds how long a resolver can hold an answer
    // that lacks this key, or holds it; a recorded schedule is exact and wins.
    let ttl_wait = Duration::seconds(i64::from(default_ttl));
    if let Some(inactive) = passed(inactive) {
        // Its signatures outlive it in caches for the TTL of the RRsets it
        // signed, which a zone signed elsewhere never told bindizr.
        return Ok((
            DnssecKeyState::Retired,
            inactive,
            delete.unwrap_or(now + ttl_wait),
        ));
    }
    if let Some(activate) = passed(activate) {
        return Ok((DnssecKeyState::Active, activate, activate));
    }
    if let Some(publish) = passed(publish) {
        return Ok((
            DnssecKeyState::Published,
            publish,
            activate.unwrap_or(now + ttl_wait),
        ));
    }
    match publish.or(activate) {
        Some(at) => Err(format!(
            "this key is not published until {}, so BIND does not serve it yet",
            at.format("%Y-%m-%dT%H:%M:%SZ")
        )),
        None => Ok((DnssecKeyState::Active, now, now)),
    }
}

/// Rebuild a key from its BIND key files (`K*.key` and `K*.private`),
/// validating the pair by reconstructing the signer. The zone's key layout
/// types a SEP key as the CSK or the KSK, and the private file's timing places
/// it in its rollover.
pub fn import_key(
    zone: &Zone,
    split_keys: bool,
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

    // Interpret the SEP flag using the zone's CSK or split-key layout.
    let role = match (flags, split_keys) {
        (257, false) => DnssecKeyRole::Csk,
        (257, true) => DnssecKeyRole::Ksk,
        (256, true) => DnssecKeyRole::Zsk,
        (256, false) => {
            return Err(
                "a 256-flag key is a ZSK, which a single-CSK layout does not use".to_string(),
            );
        }
        _ => {
            return Err(format!(
                "unsupported DNSKEY flags {} (expected 256 or 257)",
                flags
            ));
        }
    };

    // Reconstruct the pair to reject a private key for a different DNSKEY.
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

    // Preserve the rollover phase encoded by the private file's timing fields.
    let (state, state_changed_at, eligible_at) =
        bind_key_phase(private_key, zone.default_ttl, now)?;

    Ok(DnssecKey {
        id: 0,
        zone_id: zone.id,
        role,
        algorithm,
        key_tag: i32::from(dnskey.key_tag()),
        public_key: base64::engine::general_purpose::STANDARD.encode(dnskey.public_key()),
        private_key: secret.display_as_bind().to_string(),
        state,
        state_changed_at,
        eligible_at,
        max_signed_ttl: 0,
        created_at: now,
    })
}
