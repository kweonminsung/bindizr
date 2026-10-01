//! A zone's name, canonical by construction.

use super::{ParseNameError, classify_domain_label, has_whitespace_or_control, to_fqdn};
use crate::dns::name::MAX_DOMAIN_LEN;

/// A zone's name as rows store it: lowercase, no trailing dot, LDH labels.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ZoneName(String);

impl ZoneName {
    /// Parse operator input. Zone names take the strict LDH charset, unlike
    /// owner names, which must admit `_`-prefixed labels.
    pub fn parse(value: &str) -> Result<Self, ParseNameError> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(ParseNameError::Empty);
        }
        if has_whitespace_or_control(trimmed) {
            return Err(ParseNameError::Whitespace);
        }

        let bare = trimmed.strip_suffix('.').unwrap_or(trimmed);
        if bare.is_empty() {
            return Err(ParseNameError::Empty);
        }
        if bare.len() > MAX_DOMAIN_LEN {
            return Err(ParseNameError::TooLong);
        }
        for label in bare.split('.') {
            classify_domain_label(label, false)?;
        }

        Ok(Self(bare.to_ascii_lowercase()))
    }

    /// Wrap a name already in stored form, as read from a row.
    pub fn from_row(value: &str) -> Self {
        Self(value.trim_end_matches('.').to_ascii_lowercase())
    }

    /// Return the text representation of this zone name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The zone's labels. The LDH rule [`Self::parse`] applies leaves no
    /// escapes, so every `.` is a boundary.
    pub fn labels(&self) -> Vec<String> {
        self.0.split('.').map(str::to_string).collect()
    }

    /// The absolute form, with the trailing dot.
    pub fn to_fqdn(&self) -> String {
        to_fqdn(&self.0)
    }

    /// Encode the zone name as an absolute DNS wire-format name.
    pub fn to_wire(&self) -> Result<Vec<u8>, ParseNameError> {
        super::labels_to_wire(self.0.split('.'))
    }
}

/// Binding renders the stored form, so a query never compares a spelling
/// the parser did not produce.
impl<DB: sqlx::Database> sqlx::Type<DB> for ZoneName
where
    String: sqlx::Type<DB>,
{
    /// Return the SQL type used to store this value.
    fn type_info() -> DB::TypeInfo {
        <String as sqlx::Type<DB>>::type_info()
    }

    /// Check whether the SQL type can store this value.
    fn compatible(ty: &DB::TypeInfo) -> bool {
        <String as sqlx::Type<DB>>::compatible(ty)
    }
}

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for ZoneName
where
    String: sqlx::Encode<'q, DB>,
{
    /// Encode this value using its database representation.
    fn encode_by_ref(
        &self,
        buf: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        self.0.encode_by_ref(buf)
    }
}

/// The read half: the column holds the row form, so decoding never fails.
impl<'r, DB: sqlx::Database> sqlx::Decode<'r, DB> for ZoneName
where
    &'r str: sqlx::Decode<'r, DB>,
{
    /// Read the row form.
    fn decode(
        value: <DB as sqlx::Database>::ValueRef<'r>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        Ok(Self::from_row(<&str as sqlx::Decode<'r, DB>>::decode(
            value,
        )?))
    }
}

impl serde::Serialize for ZoneName {
    /// Serialize the zone name as its text.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

/// A name read from a file or a payload is parsed, so it is canonical like
/// every other.
impl<'de> serde::Deserialize<'de> for ZoneName {
    /// Deserialize a zone name from its text, rejecting one that does not parse.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        ZoneName::parse(&value).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Display for ZoneName {
    /// Write the zone name in its display form.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
