use chrono::{DateTime, Utc};
use sqlx::FromRow;

use super::dnssec_key::DnssecAlgorithm;

/// Name of the policy seeded at startup, used when `enable` names none.
pub const DEFAULT_DNSSEC_POLICY_NAME: &str = "default";

/// How a signed zone proves nonexistence (denial of existence).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DnssecDenial {
    /// Plain NSEC chain over the zone's names.
    Nsec,
    /// Hashed NSEC3 chain (RFC 5155), with the RFC 9276 parameters.
    Nsec3,
}

impl DnssecDenial {
    /// Storage and presentation name.
    pub fn as_str(&self) -> &'static str {
        match self {
            DnssecDenial::Nsec => "nsec",
            DnssecDenial::Nsec3 => "nsec3",
        }
    }
}

impl std::fmt::Display for DnssecDenial {
    /// Write the DNSSEC denial in its display form.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for DnssecDenial {
    type Err = String;

    /// Parse a DNSSEC denial from its text representation.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "nsec" => Ok(DnssecDenial::Nsec),
            "nsec3" => Ok(DnssecDenial::Nsec3),
            _ => Err(format!(
                "unsupported denial mode '{}' (supported: nsec, nsec3)",
                s
            )),
        }
    }
}

impl TryFrom<String> for DnssecDenial {
    type Error = String;

    /// Validate and convert the stored value into a DNSSEC denial.
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

/// A named bundle of signing parameters zones reference by id (BIND's
/// `dnssec-policy`, Knot's `policy`). Key layout, algorithm, and denial mode
/// are fixed at creation; the timing fields are editable and apply on the
/// next signing pass.
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct DnssecPolicy {
    pub id: i32,
    pub name: String,
    #[sqlx(try_from = "i32")]
    pub algorithm: DnssecAlgorithm,
    #[sqlx(try_from = "String")]
    pub denial: DnssecDenial,
    /// A KSK/ZSK pair instead of one CSK, so the ZSK rolls without touching
    /// the parent DS.
    pub split_keys: bool,
    /// Days a new signature stays valid.
    pub signature_validity_days: i32,
    /// Re-sign when a signature has fewer than this many days left; always
    /// below `signature_validity_days`.
    pub signature_refresh_days: i32,
    /// Days an active ZSK may sign before the scheduler rolls it; 0 disables
    /// scheduled rolls.
    pub zsk_lifetime_days: i32,
    pub created_at: DateTime<Utc>,
}
