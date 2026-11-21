//! An unsigned 32-bit TTL (RFC 8767, Section 4), stored in signed 64-bit columns.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use thiserror::Error;
use utoipa::openapi::RefOr;
use utoipa::openapi::schema::{KnownFormat, ObjectBuilder, Schema, SchemaFormat, Type};

/// A stored or requested TTL outside the wire range.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConvertTtlError {
    /// TTLs cannot be negative.
    #[error("invalid TTL: {ttl}")]
    Negative { ttl: i64 },
    /// Past the unsigned 32-bit wire range.
    #[error("TTL {ttl} exceeds the maximum of {}", Ttl::MAX)]
    TooLarge { ttl: i64 },
}

/// A TTL in seconds, 0 through 2^32 - 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Ttl(u32);

impl Ttl {
    /// The largest TTL (RFC 8767, Section 4).
    pub const MAX: Self = Self(u32::MAX);

    /// Construct a TTL from its unsigned wire value.
    pub const fn from_secs(secs: u32) -> Self {
        Self(secs)
    }

    /// Return the TTL in seconds, as the wire carries it.
    pub const fn as_secs(self) -> u32 {
        self.0
    }
}

impl From<u32> for Ttl {
    /// Take a wire TTL without narrowing its range.
    fn from(value: u32) -> Self {
        Self::from_secs(value)
    }
}

impl TryFrom<i64> for Ttl {
    type Error = ConvertTtlError;

    /// Validate a request or stored value against the unsigned wire range.
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        if value < 0 {
            return Err(ConvertTtlError::Negative { ttl: value });
        }
        u32::try_from(value)
            .map(Self)
            .map_err(|_| ConvertTtlError::TooLarge { ttl: value })
    }
}

impl From<Ttl> for u32 {
    /// Convert to the wire form.
    fn from(ttl: Ttl) -> Self {
        ttl.0
    }
}

impl From<Ttl> for i64 {
    /// Convert to the row form; the range invariant makes it exact.
    fn from(ttl: Ttl) -> Self {
        Self::from(ttl.0)
    }
}

impl From<domain::base::Ttl> for Ttl {
    /// Take the `domain` crate's TTL; both hold the same wire seconds.
    fn from(ttl: domain::base::Ttl) -> Self {
        Self(ttl.as_secs())
    }
}

impl From<Ttl> for domain::base::Ttl {
    /// Hand the TTL to the `domain` crate.
    fn from(ttl: Ttl) -> Self {
        Self::from_secs(ttl.0)
    }
}

impl fmt::Display for Ttl {
    /// Write the TTL in seconds.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl utoipa::PartialSchema for Ttl {
    /// Describe the wire range using the domain value's maximum.
    fn schema() -> RefOr<Schema> {
        ObjectBuilder::new()
            .schema_type(Type::Integer)
            .format(Some(SchemaFormat::KnownFormat(KnownFormat::Int64)))
            .minimum(Some(0u64))
            .maximum(Some(u64::from(Self::MAX.as_secs())))
            .examples([json!(3600)])
            .into()
    }
}

impl utoipa::ToSchema for Ttl {}

impl<DB: sqlx::Database> sqlx::Type<DB> for Ttl
where
    i64: sqlx::Type<DB>,
{
    /// Return the SQL type used to store this value.
    fn type_info() -> DB::TypeInfo {
        <i64 as sqlx::Type<DB>>::type_info()
    }

    /// Return whether the SQL type can store this value.
    fn compatible(ty: &DB::TypeInfo) -> bool {
        <i64 as sqlx::Type<DB>>::compatible(ty)
    }
}

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for Ttl
where
    i64: sqlx::Encode<'q, DB>,
{
    /// Encode this value using its database representation.
    fn encode_by_ref(
        &self,
        buffer: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<IsNull, BoxDynError> {
        i64::from(*self).encode_by_ref(buffer)
    }
}

impl<'r, DB: sqlx::Database> sqlx::Decode<'r, DB> for Ttl
where
    i64: sqlx::Decode<'r, DB>,
{
    /// Read the row form; a negative column fails the row.
    fn decode(value: <DB as sqlx::Database>::ValueRef<'r>) -> Result<Self, BoxDynError> {
        Ok(Self::try_from(<i64 as sqlx::Decode<'r, DB>>::decode(
            value,
        )?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that TTL conversion preserves every boundary of the unsigned wire range.
    #[test]
    fn ttl_preserves_unsigned_boundaries() {
        for value in [0, 2_147_483_647, 2_147_483_648, u32::MAX] {
            let ttl = Ttl::try_from(i64::from(value)).unwrap();
            assert_eq!(ttl.as_secs(), value);
            assert_eq!(i64::from(ttl), i64::from(value));
            let json = serde_json::to_string(&ttl).unwrap();
            assert_eq!(serde_json::from_str::<Ttl>(&json).unwrap(), ttl);
        }

        for value in [-1i64, i64::from(u32::MAX) + 1] {
            assert!(Ttl::try_from(value).is_err());
        }
    }
}
