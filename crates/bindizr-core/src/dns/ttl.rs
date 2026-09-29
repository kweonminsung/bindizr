//! A time to live as one value with two forms: the unsigned 32-bit field the
//! wire carries and the signed 32-bit column a row stores. RFC 2181,
//! Section 8 caps a TTL at 2^31 - 1, so both forms hold every valid value.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A TTL in seconds, 0 through 2^31 - 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct Ttl(u32);

/// A TTL outside the range both forms hold.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConvertTtlError {
    /// Rows are stored as `i32`, so a negative one is corrupt data.
    #[error("Invalid TTL: {ttl}")]
    Negative { ttl: i32 },
    /// Past 2^31 - 1, which RFC 2181, Section 8 reads as zero.
    #[error("TTL {ttl} exceeds the maximum of {}", i32::MAX)]
    TooLarge { ttl: u32 },
}

impl Ttl {
    /// The largest TTL (RFC 2181, Section 8).
    pub const MAX: Ttl = Ttl(i32::MAX as u32);

    /// A TTL known to be in range, such as a literal; wire input goes
    /// through `TryFrom` instead.
    ///
    /// # Panics
    ///
    /// Past [`Ttl::MAX`].
    pub const fn from_secs(secs: u32) -> Self {
        assert!(secs <= Self::MAX.0, "TTL exceeds 2^31 - 1");
        Ttl(secs)
    }

    /// The TTL in seconds, as the wire carries it.
    pub const fn as_secs(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for Ttl {
    type Error = ConvertTtlError;

    /// Take a wire TTL, refused past the maximum.
    fn try_from(ttl: u32) -> Result<Self, Self::Error> {
        if ttl > Self::MAX.0 {
            return Err(ConvertTtlError::TooLarge { ttl });
        }
        Ok(Ttl(ttl))
    }
}

impl TryFrom<i32> for Ttl {
    type Error = ConvertTtlError;

    /// Read a row's TTL; a negative one is corrupt data.
    fn try_from(ttl: i32) -> Result<Self, Self::Error> {
        u32::try_from(ttl)
            .map(Ttl)
            .map_err(|_| ConvertTtlError::Negative { ttl })
    }
}

impl From<Ttl> for u32 {
    /// The wire form.
    fn from(ttl: Ttl) -> Self {
        ttl.0
    }
}

impl From<Ttl> for i32 {
    /// The row form; the range invariant makes it exact.
    fn from(ttl: Ttl) -> Self {
        ttl.0 as i32
    }
}

impl fmt::Display for Ttl {
    /// Write the TTL in seconds.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl<DB: sqlx::Database> sqlx::Type<DB> for Ttl
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

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for Ttl
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

impl<'r, DB: sqlx::Database> sqlx::Decode<'r, DB> for Ttl
where
    i32: sqlx::Decode<'r, DB>,
{
    /// Read the row form; a negative column fails the row.
    fn decode(
        value: <DB as sqlx::Database>::ValueRef<'r>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        Ok(Ttl::try_from(<i32 as sqlx::Decode<'r, DB>>::decode(
            value,
        )?)?)
    }
}
