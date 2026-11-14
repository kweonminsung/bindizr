//! RFC 1982 serial arithmetic, stored losslessly in signed 64-bit columns.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use thiserror::Error;
use utoipa::openapi::RefOr;
use utoipa::openapi::schema::{KnownFormat, ObjectBuilder, Schema, SchemaFormat, Type};

/// A serial that cannot cross between its row form and its wire form.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConvertSerialError {
    #[error("invalid DNS serial: {serial}; expected an unsigned 32-bit value")]
    OutOfRange { serial: i64 },
}

/// A zone's SOA serial, in its wire form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Serial(u32);

impl Serial {
    /// The largest wire serial (RFC 1982, Section 2).
    pub const MAX: Self = Self(u32::MAX);

    /// Return the serial as the wire carries it.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Return whether this serial advances `other` under RFC 1982, Section 3.2.
    /// The undefined half-range distance does not establish an advance.
    pub fn is_newer_than(self, other: Self) -> bool {
        matches!(self.0.wrapping_sub(other.0), 1..=0x7fff_ffff)
    }

    /// Advance modulo 2^32 (RFC 1982, Section 3.1), passing over zero (RFC 2136,
    /// Section 7.11: older secondaries read it as a zone to fetch afresh).
    pub fn next(self) -> Self {
        match self.0.wrapping_add(1) {
            0 => Self(1),
            next => Self(next),
        }
    }
}

impl From<u32> for Serial {
    /// Take a wire serial as it is.
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<Serial> for u32 {
    /// Convert to the wire form.
    fn from(serial: Serial) -> Self {
        serial.0
    }
}

impl TryFrom<i64> for Serial {
    type Error = ConvertSerialError;

    /// Read a stored serial, rejecting values outside the DNS wire range.
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        u32::try_from(value)
            .map(Self)
            .map_err(|_| ConvertSerialError::OutOfRange { serial: value })
    }
}

impl TryFrom<i32> for Serial {
    type Error = ConvertSerialError;

    /// Convert a signed application value without reinterpreting negative bits.
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Self::try_from(i64::from(value))
    }
}

impl From<Serial> for i64 {
    /// Widen the wire serial into its lossless database representation.
    fn from(serial: Serial) -> Self {
        Self::from(serial.0)
    }
}

impl fmt::Display for Serial {
    /// Write the serial in decimal.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl utoipa::PartialSchema for Serial {
    /// Describe the unsigned wire range with a format that holds every serial.
    fn schema() -> RefOr<Schema> {
        ObjectBuilder::new()
            .schema_type(Type::Integer)
            .format(Some(SchemaFormat::KnownFormat(KnownFormat::Int64)))
            .minimum(Some(0u64))
            .maximum(Some(u64::from(Self::MAX.as_u32())))
            .examples([json!(42)])
            .into()
    }
}

impl utoipa::ToSchema for Serial {}

impl<DB: sqlx::Database> sqlx::Type<DB> for Serial
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

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for Serial
where
    i64: sqlx::Encode<'q, DB>,
{
    /// Encode this value using its database representation: every wire serial in
    /// the signed 64-bit row form.
    fn encode_by_ref(
        &self,
        buffer: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<IsNull, BoxDynError> {
        i64::from(*self).encode_by_ref(buffer)
    }
}

impl<'r, DB: sqlx::Database> sqlx::Decode<'r, DB> for Serial
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

    /// Verify that advancing wraps past the maximum to one, never zero (RFC 2136, Section 7.11).
    #[test]
    fn next_skips_zero_when_wrapping() {
        for (serial, next) in [(0, 1), (1, 2), (u32::MAX - 1, u32::MAX), (u32::MAX, 1)] {
            assert_eq!(Serial::from(serial).next(), Serial::from(next));
        }
    }

    /// Verify that ordinary, wrapped, equal, and undefined serial comparisons follow RFC 1982.
    #[test]
    fn is_newer_than_follows_rfc1982_arithmetic() {
        for (candidate, current, newer) in [
            (11, 10, true),
            (10, 10, false),
            (9, 10, false),
            (0, u32::MAX, true),
            (u32::MAX, 0, false),
            (0x8000_0000, 0, false),
            (0, 0x8000_0000, false),
            (0x7fff_ffff, 0, true),
        ] {
            assert_eq!(
                Serial::from(candidate).is_newer_than(Serial::from(current)),
                newer
            );
        }
    }
}
