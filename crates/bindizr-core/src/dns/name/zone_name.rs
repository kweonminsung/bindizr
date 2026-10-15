//! A zone's name, canonical by construction.

use super::{
    ParseNameError, decode_name_labels, labels_to_presentation, to_fqdn, trim_presentation_name,
};

/// A zone's name as rows store it: escaped octet labels, ASCII-folded, without a trailing dot.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ZoneName(String);

impl ZoneName {
    /// Parse a zone name using DNS octet and length rules (RFC 2181, Section 11).
    pub fn parse(value: &str) -> Result<Self, ParseNameError> {
        let trimmed = trim_presentation_name(value);
        if trimmed.is_empty() || trimmed == "." {
            return Err(ParseNameError::Empty);
        }
        let (labels, _) = decode_name_labels(trimmed)?;
        Ok(Self(labels_to_presentation(&labels)))
    }

    /// Wrap a name already in stored form, as read from a row.
    pub fn from_row(value: &str) -> Self {
        Self::parse(value).expect("zone name validated before storage")
    }

    /// Return the text representation of this zone name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The zone's decoded, case-folded octet labels.
    pub fn labels(&self) -> Vec<Vec<u8>> {
        decode_name_labels(&self.0).expect("validated zone name").0
    }

    /// The absolute form, with the trailing dot.
    pub fn to_fqdn(&self) -> String {
        to_fqdn(&self.0)
    }

    /// Encode the zone name as an absolute DNS wire-format name.
    pub fn to_wire(&self) -> Result<Vec<u8>, ParseNameError> {
        super::labels_to_wire(self.labels().iter().map(Vec::as_slice))
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

/// Decode persisted names with the same octet and length validation as input.
impl<'r, DB: sqlx::Database> sqlx::Decode<'r, DB> for ZoneName
where
    &'r str: sqlx::Decode<'r, DB>,
{
    /// Read the row form.
    fn decode(
        value: <DB as sqlx::Database>::ValueRef<'r>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        Ok(Self::parse(<&str as sqlx::Decode<'r, DB>>::decode(value)?)?)
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
