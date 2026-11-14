//! A DNSKEY key tag: unsigned 16-bit wire value, signed 32-bit storage (RFC 4034, Appendix B).

use std::fmt;

use serde::{Deserialize, Serialize};
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use thiserror::Error;

/// A key tag, 0 through 65535.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyTag(u16);

/// A row's key tag outside the 16 bits the wire carries: corrupt data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid key tag: {key_tag}")]
pub struct ConvertKeyTagError {
    key_tag: i32,
}

impl KeyTag {
    /// Return the key tag as the wire carries it.
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

impl From<u16> for KeyTag {
    /// Take a wire key tag.
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl TryFrom<i32> for KeyTag {
    type Error = ConvertKeyTagError;

    /// Read a row's key tag; one outside 16 bits is corrupt data.
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        u16::try_from(value)
            .map(Self)
            .map_err(|_| ConvertKeyTagError { key_tag: value })
    }
}

impl From<KeyTag> for u16 {
    /// Convert to the wire form.
    fn from(key_tag: KeyTag) -> Self {
        key_tag.0
    }
}

impl From<KeyTag> for i32 {
    /// Convert to the row form.
    fn from(key_tag: KeyTag) -> Self {
        Self::from(key_tag.0)
    }
}

impl fmt::Display for KeyTag {
    /// Write the key tag, honouring a width so a BIND file name can pad it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl<DB: sqlx::Database> sqlx::Type<DB> for KeyTag
where
    i32: sqlx::Type<DB>,
{
    /// Return the SQL type used to store this value.
    fn type_info() -> DB::TypeInfo {
        <i32 as sqlx::Type<DB>>::type_info()
    }

    /// Return whether the SQL type can store this value.
    fn compatible(ty: &DB::TypeInfo) -> bool {
        <i32 as sqlx::Type<DB>>::compatible(ty)
    }
}

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for KeyTag
where
    i32: sqlx::Encode<'q, DB>,
{
    /// Encode this value using its database representation.
    fn encode_by_ref(
        &self,
        buffer: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<IsNull, BoxDynError> {
        i32::from(*self).encode_by_ref(buffer)
    }
}

impl<'r, DB: sqlx::Database> sqlx::Decode<'r, DB> for KeyTag
where
    i32: sqlx::Decode<'r, DB>,
{
    /// Read the row form; a column outside 16 bits fails the row.
    fn decode(value: <DB as sqlx::Database>::ValueRef<'r>) -> Result<Self, BoxDynError> {
        Ok(Self::try_from(<i32 as sqlx::Decode<'r, DB>>::decode(
            value,
        )?)?)
    }
}
