//! A DNSKEY key tag (RFC 4034, Appendix B) as one value with two forms: the
//! unsigned 16-bit field DS and RRSIG records carry and the signed 32-bit
//! column a row stores.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A key tag, 0 through 65535.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyTag(u16);

/// A row's key tag outside the 16 bits the wire carries: corrupt data.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("Invalid key tag: {key_tag}")]
pub struct ConvertKeyTagError {
    key_tag: i32,
}

impl KeyTag {
    /// The key tag as the wire carries it.
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

impl From<u16> for KeyTag {
    /// Take a wire key tag.
    fn from(key_tag: u16) -> Self {
        KeyTag(key_tag)
    }
}

impl TryFrom<i32> for KeyTag {
    type Error = ConvertKeyTagError;

    /// Read a row's key tag; one outside 16 bits is corrupt data.
    fn try_from(key_tag: i32) -> Result<Self, Self::Error> {
        u16::try_from(key_tag)
            .map(KeyTag)
            .map_err(|_| ConvertKeyTagError { key_tag })
    }
}

impl From<KeyTag> for u16 {
    /// The wire form.
    fn from(key_tag: KeyTag) -> Self {
        key_tag.0
    }
}

impl From<KeyTag> for i32 {
    /// The row form.
    fn from(key_tag: KeyTag) -> Self {
        i32::from(key_tag.0)
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
    /// The row form's column type.
    fn type_info() -> DB::TypeInfo {
        <i32 as sqlx::Type<DB>>::type_info()
    }

    /// Whether the column can hold the row form.
    fn compatible(ty: &DB::TypeInfo) -> bool {
        <i32 as sqlx::Type<DB>>::compatible(ty)
    }
}

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for KeyTag
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

impl<'r, DB: sqlx::Database> sqlx::Decode<'r, DB> for KeyTag
where
    i32: sqlx::Decode<'r, DB>,
{
    /// Read the row form; a column outside 16 bits fails the row.
    fn decode(
        value: <DB as sqlx::Database>::ValueRef<'r>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        Ok(KeyTag::try_from(<i32 as sqlx::Decode<'r, DB>>::decode(
            value,
        )?)?)
    }
}
