//! The SOA serial as one value with two forms: the unsigned 32-bit field the
//! wire carries (RFC 1035, Section 3.3.13) and the signed 32-bit column a row
//! stores, so a serial bindizr writes stays at or below `i32::MAX`.

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
    /// Rows are stored as `i32`, so a negative one is corrupt data.
    #[error("Invalid DNS serial: {serial}")]
    Negative { serial: i32 },
    /// One past `i32::MAX` names nothing bindizr could have written.
    #[error("serial {serial} is beyond the stored range of {}", i32::MAX)]
    BeyondStoredRange { serial: u32 },
}

impl Serial {
    /// The largest serial a row can hold.
    pub const MAX_STORED: Serial = Serial(i32::MAX as u32);

    /// The serial as the wire carries it.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// The serial one step ahead, or `None` at the stored ceiling: a
    /// saturating step would repeat a serial silently.
    pub fn next(self) -> Option<Serial> {
        (self < Self::MAX_STORED).then(|| Serial(self.0 + 1))
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

impl TryFrom<i32> for Serial {
    type Error = ConvertSerialError;

    /// Read a row's serial; a negative one is corrupt data.
    fn try_from(serial: i32) -> Result<Self, Self::Error> {
        u32::try_from(serial)
            .map(Serial)
            .map_err(|_| ConvertSerialError::Negative { serial })
    }
}

impl TryFrom<Serial> for i32 {
    type Error = ConvertSerialError;

    /// The row form, refused past the stored range.
    fn try_from(serial: Serial) -> Result<Self, Self::Error> {
        i32::try_from(serial.0)
            .map_err(|_| ConvertSerialError::BeyondStoredRange { serial: serial.0 })
    }
}

impl fmt::Display for Serial {
    /// Write the serial in decimal.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl<DB: sqlx::Database> sqlx::Type<DB> for Serial
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

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for Serial
where
    i32: sqlx::Encode<'q, DB>,
{
    /// Bind the row form; a serial past the stored range fails the query.
    fn encode_by_ref(
        &self,
        buf: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        i32::try_from(*self)?.encode_by_ref(buf)
    }
}

impl<'r, DB: sqlx::Database> sqlx::Decode<'r, DB> for Serial
where
    i32: sqlx::Decode<'r, DB>,
{
    /// Read the row form; a negative column fails the row.
    fn decode(
        value: <DB as sqlx::Database>::ValueRef<'r>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        Ok(Serial::try_from(<i32 as sqlx::Decode<'r, DB>>::decode(
            value,
        )?)?)
    }
}
