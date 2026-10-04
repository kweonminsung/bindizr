use std::fmt;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use thiserror::Error;

use super::dnssec_key::DnssecAlgorithm;

/// Name of the policy seeded at startup, used when `enable` names none.
pub const DEFAULT_DNSSEC_POLICY_NAME: &str = "default";

/// A denial mode outside NSEC and NSEC3.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unsupported denial mode '{value}' (supported: nsec, nsec3)")]
pub struct ParseDenialError {
    pub value: String,
}

/// How a signed zone proves nonexistence (denial of existence).
#[derive(
    Debug, PartialEq, Eq, Clone, Copy, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum DnssecDenial {
    /// Plain NSEC chain over the zone's names.
    Nsec,
    /// Hashed NSEC3 chain (RFC 5155), with the RFC 9276 parameters.
    Nsec3,
}

impl DnssecDenial {
    /// Storage name, as the columns and the API spell it.
    pub fn as_str(&self) -> &'static str {
        match self {
            DnssecDenial::Nsec => "nsec",
            DnssecDenial::Nsec3 => "nsec3",
        }
    }
}

impl std::fmt::Display for DnssecDenial {
    /// Write the denial mode in the upper case the DNSSEC documents use.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DnssecDenial::Nsec => "NSEC",
            DnssecDenial::Nsec3 => "NSEC3",
        })
    }
}

impl std::str::FromStr for DnssecDenial {
    type Err = ParseDenialError;

    /// Parse a DNSSEC denial from its text representation.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "nsec" => Ok(DnssecDenial::Nsec),
            "nsec3" => Ok(DnssecDenial::Nsec3),
            _ => Err(ParseDenialError {
                value: s.to_string(),
            }),
        }
    }
}

impl TryFrom<String> for DnssecDenial {
    type Error = ParseDenialError;

    /// Validate and convert the stored value into a DNSSEC denial.
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

id_newtype!(
    /// The id of a DNSSEC policy row.
    PolicyId
);

/// A named signing policy: key layout, algorithm, and denial mode are fixed
/// at creation; timing changes take effect on the next signing pass.
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct DnssecPolicy {
    pub id: PolicyId,
    pub name: String,
    #[sqlx(try_from = "i32")]
    pub algorithm: DnssecAlgorithm,
    #[sqlx(try_from = "String")]
    pub denial: DnssecDenial,
    /// A KSK/ZSK pair instead of one CSK, so the ZSK rolls without touching
    /// the parent DS.
    pub split_keys: bool,
    /// Days a new signature stays valid.
    pub signature_validity_days: Days,
    /// Re-sign when a signature has fewer than this many days left; always
    /// below `signature_validity_days`.
    pub signature_refresh_days: Days,
    /// Days an active ZSK may sign before the scheduler rolls it; 0 disables
    /// scheduled rolls.
    pub zsk_lifetime_days: Days,
    pub created_at: DateTime<Utc>,
}

impl DnssecPolicy {
    /// Whether this is the built-in `default` policy, which cannot be deleted.
    pub fn is_builtin(&self) -> bool {
        self.name == DEFAULT_DNSSEC_POLICY_NAME
    }

    /// Describe the policy's key layout for validation errors.
    pub fn key_layout(&self) -> &'static str {
        if self.split_keys {
            "split KSK/ZSK keys"
        } else {
            "a single CSK"
        }
    }

    /// Spread expirations over half the available window to avoid zone-wide
    /// re-signing while keeping the earliest signature outside its refresh window.
    pub fn expiration_jitter_secs(&self) -> i64 {
        (self.signature_validity_secs() - self.signature_refresh_secs()).max(0) / 2
    }

    /// How long a signature stays valid, in seconds.
    pub fn signature_validity_secs(&self) -> i64 {
        self.signature_validity_days.to_duration().num_seconds()
    }

    /// How long before it expires a signature is renewed, in seconds.
    pub fn signature_refresh_secs(&self) -> i64 {
        self.signature_refresh_days.to_duration().num_seconds()
    }
}

/// A count of days as one value with two forms: the unsigned count a payload
/// carries and the signed 32-bit column a row stores, 0 through 2^31 - 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct Days(u32);

/// A day count outside the range both forms hold.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConvertDaysError {
    /// Rows are stored as `i32`, so a negative one is corrupt data.
    #[error("invalid day count: {days}")]
    Negative { days: i32 },
    /// Past 2^31 - 1, which the row form cannot hold.
    #[error("day count {days} exceeds the maximum of {}", i32::MAX)]
    TooLarge { days: u32 },
}

impl Days {
    /// The largest count the row form holds.
    pub const MAX: Days = Days(i32::MAX as u32);

    /// The count of days.
    pub const fn as_days(self) -> u32 {
        self.0
    }

    /// The count as a duration.
    pub fn to_duration(self) -> Duration {
        Duration::days(i64::from(self.0))
    }
}

impl TryFrom<u32> for Days {
    type Error = ConvertDaysError;

    /// Take a payload's count, refused past the maximum.
    fn try_from(days: u32) -> Result<Self, Self::Error> {
        if days > Self::MAX.0 {
            return Err(ConvertDaysError::TooLarge { days });
        }
        Ok(Days(days))
    }
}

impl TryFrom<i32> for Days {
    type Error = ConvertDaysError;

    /// Read a row's count; a negative one is corrupt data.
    fn try_from(days: i32) -> Result<Self, Self::Error> {
        u32::try_from(days)
            .map(Days)
            .map_err(|_| ConvertDaysError::Negative { days })
    }
}

impl From<Days> for u32 {
    /// The payload form.
    fn from(days: Days) -> Self {
        days.0
    }
}

impl From<Days> for i32 {
    /// The row form; the range invariant makes it exact.
    fn from(days: Days) -> Self {
        days.0 as i32
    }
}

impl fmt::Display for Days {
    /// Write the count of days.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl<DB: sqlx::Database> sqlx::Type<DB> for Days
where
    i32: sqlx::Type<DB>,
{
    /// The row form's column type.
    fn type_info() -> DB::TypeInfo {
        <i32 as sqlx::Type<DB>>::type_info()
    }

    /// Whether the column can hold the row form.
    fn compatible(ty: &DB::TypeInfo) -> bool {
        <i32 as sqlx::Type<DB>>::compatible(ty)
    }
}

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for Days
where
    i32: sqlx::Encode<'q, DB>,
{
    /// Bind the row form.
    fn encode_by_ref(
        &self,
        buf: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        i32::from(*self).encode_by_ref(buf)
    }
}

impl<'r, DB: sqlx::Database> sqlx::Decode<'r, DB> for Days
where
    i32: sqlx::Decode<'r, DB>,
{
    /// Read the row form; a negative column fails the row.
    fn decode(
        value: <DB as sqlx::Database>::ValueRef<'r>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        Ok(Days::try_from(<i32 as sqlx::Decode<'r, DB>>::decode(
            value,
        )?)?)
    }
}

/// How a zone divides DNSSEC signing responsibilities among keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecKeyLayout {
    Csk,
    Split,
}

impl DnssecKeyLayout {
    /// Interpret the stored split-key setting at a key-operation boundary.
    pub fn from_split_keys(split_keys: bool) -> Self {
        if split_keys { Self::Split } else { Self::Csk }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Verify that `DnssecDenial` has one spelling across `as_str`, serde, and `FromStr`.
    #[test]
    fn dnssec_denial_spells_itself_once() {
        for value in [DnssecDenial::Nsec, DnssecDenial::Nsec3] {
            assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
            assert_eq!(
                serde_json::from_value::<DnssecDenial>(json!(value.as_str())).unwrap(),
                value
            );
            assert_eq!(value.as_str().parse::<DnssecDenial>().unwrap(), value);
        }
    }
}
