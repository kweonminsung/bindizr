//! An SOA REFRESH, RETRY or EXPIRE interval as one value with two forms: the
//! unsigned 32-bit field the wire carries (RFC 1035, Section 3.3.13) and the
//! signed 32-bit column a row stores, so a stored interval stays below 2^31.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// An SOA interval in seconds, 0 through 2^31 - 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct SoaInterval(u32);

/// An SOA interval outside the range both forms hold.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConvertSoaIntervalError {
    /// Rows are stored as `i32`, so a negative one is corrupt data.
    #[error("Invalid SOA interval: {secs}")]
    Negative { secs: i32 },
    /// Past 2^31 - 1, which the row form cannot hold.
    #[error("SOA interval {secs} exceeds the maximum of {}", i32::MAX)]
    TooLarge { secs: u32 },
}

impl SoaInterval {
    /// The largest interval the row form holds.
    pub const MAX: SoaInterval = SoaInterval(i32::MAX as u32);

    /// An interval known to be in range, such as a literal; wire input goes
    /// through `TryFrom` instead.
    ///
    /// # Panics
    ///
    /// Past [`SoaInterval::MAX`].
    pub const fn from_secs(secs: u32) -> Self {
        assert!(secs <= Self::MAX.0, "SOA interval exceeds 2^31 - 1");
        SoaInterval(secs)
    }

    /// The interval in seconds, as the wire carries it.
    pub const fn as_secs(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for SoaInterval {
    type Error = ConvertSoaIntervalError;

    /// Take a wire interval, refused past the maximum.
    fn try_from(secs: u32) -> Result<Self, Self::Error> {
        if secs > Self::MAX.0 {
            return Err(ConvertSoaIntervalError::TooLarge { secs });
        }
        Ok(SoaInterval(secs))
    }
}

impl TryFrom<i32> for SoaInterval {
    type Error = ConvertSoaIntervalError;

    /// Read a row's interval; a negative one is corrupt data.
    fn try_from(secs: i32) -> Result<Self, Self::Error> {
        u32::try_from(secs)
            .map(SoaInterval)
            .map_err(|_| ConvertSoaIntervalError::Negative { secs })
    }
}

impl From<SoaInterval> for u32 {
    /// The wire form.
    fn from(interval: SoaInterval) -> Self {
        interval.0
    }
}

impl From<SoaInterval> for i32 {
    /// The row form; the range invariant makes it exact.
    fn from(interval: SoaInterval) -> Self {
        interval.0 as i32
    }
}

impl fmt::Display for SoaInterval {
    /// Write the interval in seconds.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl<DB: sqlx::Database> sqlx::Type<DB> for SoaInterval
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

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for SoaInterval
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

impl<'r, DB: sqlx::Database> sqlx::Decode<'r, DB> for SoaInterval
where
    i32: sqlx::Decode<'r, DB>,
{
    /// Read the row form; a negative column fails the row.
    fn decode(
        value: <DB as sqlx::Database>::ValueRef<'r>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        Ok(SoaInterval::try_from(
            <i32 as sqlx::Decode<'r, DB>>::decode(value)?,
        )?)
    }
}
