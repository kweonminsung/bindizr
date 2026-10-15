//! RFC 1982 serial arithmetic, stored losslessly in signed 64-bit columns.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A zone's SOA serial, in its wire form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Serial(u32);

/// A serial that cannot cross between its row form and its wire form.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConvertSerialError {
    #[error("invalid DNS serial: {serial}; expected an unsigned 32-bit value")]
    OutOfRange { serial: i64 },
}

impl Serial {
    /// The largest wire serial (RFC 1982, Section 2).
    pub const MAX: Serial = Serial(u32::MAX);

    /// The serial as the wire carries it.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Whether this serial advances `other` under RFC 1982, Section 3.2.
    /// The undefined half-range distance does not establish an advance.
    pub fn is_newer_than(self, other: Serial) -> bool {
        matches!(self.0.wrapping_sub(other.0), 1..=0x7fff_ffff)
    }

    /// Advance modulo 2^32 (RFC 1982, Section 3.1), including MAX to zero.
    pub fn next(self) -> Serial {
        Serial(self.0.wrapping_add(1))
    }
}

impl From<u32> for Serial {
    /// Take a wire serial as it is.
    fn from(serial: u32) -> Self {
        Serial(serial)
    }
}

impl From<Serial> for u32 {
    /// The wire form.
    fn from(serial: Serial) -> Self {
        serial.0
    }
}

impl TryFrom<i64> for Serial {
    type Error = ConvertSerialError;

    /// Read a stored serial, rejecting values outside the DNS wire range.
    fn try_from(serial: i64) -> Result<Self, Self::Error> {
        u32::try_from(serial)
            .map(Serial)
            .map_err(|_| ConvertSerialError::OutOfRange { serial })
    }
}

impl TryFrom<i32> for Serial {
    type Error = ConvertSerialError;

    /// Convert a signed application value without reinterpreting negative bits.
    fn try_from(serial: i32) -> Result<Self, Self::Error> {
        Self::try_from(i64::from(serial))
    }
}

impl From<Serial> for i64 {
    /// Widen the wire serial into its lossless database representation.
    fn from(serial: Serial) -> Self {
        i64::from(serial.0)
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
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        use utoipa::openapi::schema::{KnownFormat, ObjectBuilder, SchemaFormat, Type};

        ObjectBuilder::new()
            .schema_type(Type::Integer)
            .format(Some(SchemaFormat::KnownFormat(KnownFormat::Int64)))
            .minimum(Some(0_u64))
            .maximum(Some(u64::from(Self::MAX.as_u32())))
            .examples([serde_json::json!(42)])
            .into()
    }
}

impl utoipa::ToSchema for Serial {}

impl<DB: sqlx::Database> sqlx::Type<DB> for Serial
where
    i64: sqlx::Type<DB>,
{
    /// The row form's column type.
    fn type_info() -> DB::TypeInfo {
        <i64 as sqlx::Type<DB>>::type_info()
    }

    /// Whether the column can hold the row form.
    fn compatible(ty: &DB::TypeInfo) -> bool {
        <i64 as sqlx::Type<DB>>::compatible(ty)
    }
}

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for Serial
where
    i64: sqlx::Encode<'q, DB>,
{
    /// Bind every wire serial in the signed 64-bit row form.
    fn encode_by_ref(
        &self,
        buf: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        i64::from(*self).encode_by_ref(buf)
    }
}

impl<'r, DB: sqlx::Database> sqlx::Decode<'r, DB> for Serial
where
    i64: sqlx::Decode<'r, DB>,
{
    /// Read the row form; a negative column fails the row.
    fn decode(
        value: <DB as sqlx::Database>::ValueRef<'r>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        Ok(Serial::try_from(<i64 as sqlx::Decode<'r, DB>>::decode(
            value,
        )?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::Serial;

    /// Check ordinary, wrapped, equal, and undefined serial comparisons.
    #[test]
    fn newer_follows_rfc1982_arithmetic() {
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
