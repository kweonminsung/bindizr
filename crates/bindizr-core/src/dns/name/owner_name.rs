//! A record's owner name, held as decoded labels.

use std::fmt;

use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;

use crate::dns::name;
use crate::dns::name::{EncodeWireNameError, ParseNameError, WireName, ZoneName};

/// Decoded zone-relative labels; the apex is empty and in-label dots remain data.
/// Construction lowercases labels for case-insensitive `Eq`/`Hash` (RFC 4343).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OwnerName(Vec<Vec<u8>>);

impl OwnerName {
    /// How the apex is spelled in input and in presentation. Rows hold it out
    /// of band, as the empty string.
    pub const APEX: &'static str = "@";

    /// Create the relative owner name for the zone apex.
    pub fn apex() -> Self {
        Self(Vec::new())
    }

    /// Return whether this owner names the zone apex.
    pub fn is_apex(&self) -> bool {
        self.0.is_empty()
    }

    /// Return the owner's decoded DNS labels.
    pub fn labels(&self) -> &[Vec<u8>] {
        &self.0
    }

    /// Parse `@`, relative names, or absolute names inside `zone_name` into octet labels.
    /// Validate wire lengths without imposing hostname character rules.
    pub fn parse_in_zone(value: &str, zone_name: &ZoneName) -> Result<Self, ParseNameError> {
        let trimmed = name::trim_presentation_name(value);

        if trimmed.trim_end_matches('.').is_empty() {
            return Err(ParseNameError::Empty);
        }
        if trimmed == Self::APEX {
            return Ok(Self::apex());
        }

        let (mut labels, absolute) = name::decode_name_labels(trimmed)?;
        let zone_labels = zone_name.labels();

        // A relative name that happens to end in the zone was already absolute.
        match relative_label_count(&labels, &zone_labels) {
            Some(count) => {
                labels.truncate(count);
                labels.shrink_to_fit();
                Ok(Self(labels))
            }
            None if absolute => Err(ParseNameError::OutsideZone),
            // Relative input grows by the zone it is qualified with, which is
            // what can push it past the length `decode_name_labels` checked.
            None => {
                name::classify_wire_len(&labels, &zone_labels)?;
                Ok(Self(labels))
            }
        }
    }

    /// Parse an absolute name inside `zone_name`, even without a trailing root dot.
    /// Relative client input belongs to [`Self::parse_in_zone`].
    pub fn parse_absolute_in_zone(
        value: &str,
        zone_name: &ZoneName,
    ) -> Result<Self, ParseNameError> {
        let trimmed = name::trim_presentation_name(value);

        // No zone is the root, so the root lies outside every zone.
        if trimmed == "." {
            return Err(ParseNameError::OutsideZone);
        }

        // `@` is client shorthand, not a name: here it is one label like any other.
        let (mut labels, _) = name::decode_name_labels(trimmed)?;

        let count = relative_label_count(&labels, &zone_name.labels())
            .ok_or(ParseNameError::OutsideZone)?;
        labels.truncate(count);
        labels.shrink_to_fit();
        Ok(Self(labels))
    }

    /// Wrap a name already in stored form, as read from a row.
    pub fn from_row(value: &str) -> Self {
        if value.is_empty() {
            return Self::apex();
        }

        match name::decode_name_labels(value) {
            Ok((labels, _)) => Self(labels),
            // An externally corrupted row becomes one literal label; splitting it
            // would invent a different name.
            Err(error) => {
                log::error!("undecodable owner name in a record row: {value} ({error})");
                Self(vec![value.as_bytes().to_ascii_lowercase()])
            }
        }
    }

    /// Return the form rows store: empty at the apex, so no label can collide with
    /// it, otherwise the escaped labels joined with `.`.
    pub fn to_stored(&self) -> String {
        if self.is_apex() {
            return String::new();
        }

        self.to_presentation()
    }

    /// Encode the wire form within `zone_name`: this owner's labels, the zone's,
    /// then the root.
    pub fn to_wire(&self, zone_name: &ZoneName) -> Result<Vec<u8>, ParseNameError> {
        let zone_labels = zone_name.labels();
        name::labels_to_wire(
            self.0
                .iter()
                .map(Vec::as_slice)
                .chain(zone_labels.iter().map(Vec::as_slice)),
        )
    }

    /// Convert the owner, absolute within `zone_name`, into the `domain`
    /// crate's name form.
    pub fn to_wire_name(&self, zone_name: &ZoneName) -> Result<WireName, EncodeWireNameError> {
        name::wire_to_name(self.to_wire(zone_name)?)
    }

    /// Return the absolute form within `zone_name`.
    pub fn to_fqdn(&self, zone_name: &ZoneName) -> String {
        if self.is_apex() {
            return zone_name.to_fqdn();
        }

        format!("{}.{}", self.to_presentation(), zone_name.to_fqdn())
    }

    /// Render this owner's labels in presentation form, with the required escapes.
    fn to_presentation(&self) -> String {
        name::labels_to_presentation(&self.0)
    }

    /// Return whether this owner is `other` or sits under it, compared label by label.
    pub fn is_same_or_under(&self, other: &Self) -> bool {
        name::is_label_suffix(&self.0, &other.0)
    }
}

/// The write half: binding renders [`OwnerName::to_stored`], so a query cannot
/// reach a column through [`std::fmt::Display`], whose apex is `@`.
impl<DB: sqlx::Database> sqlx::Type<DB> for OwnerName
where
    String: sqlx::Type<DB>,
{
    /// Return the SQL type used to store this value.
    fn type_info() -> DB::TypeInfo {
        <String as sqlx::Type<DB>>::type_info()
    }

    /// Return whether the SQL type can store this value.
    fn compatible(ty: &DB::TypeInfo) -> bool {
        <String as sqlx::Type<DB>>::compatible(ty)
    }
}

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for OwnerName
where
    String: sqlx::Encode<'q, DB>,
{
    /// Encode this value using its database representation.
    fn encode_by_ref(
        &self,
        buffer: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<IsNull, BoxDynError> {
        self.to_stored().encode_by_ref(buffer)
    }
}

/// The read half: the column holds the row form, so decoding never fails.
impl<'r, DB: sqlx::Database> sqlx::Decode<'r, DB> for OwnerName
where
    &'r str: sqlx::Decode<'r, DB>,
{
    /// Read the row form.
    fn decode(value: <DB as sqlx::Database>::ValueRef<'r>) -> Result<Self, BoxDynError> {
        Ok(Self::from_row(<&str as sqlx::Decode<'r, DB>>::decode(
            value,
        )?))
    }
}

/// Presentation form, as input spells it: `@` at the apex; rows take
/// [`OwnerName::to_stored`].
impl fmt::Display for OwnerName {
    /// Write the owner name in its display form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_apex() {
            return f.write_str(Self::APEX);
        }
        f.write_str(&self.to_presentation())
    }
}

/// Count the labels before `zone` in `name`, or return `None` for a name outside it.
fn relative_label_count(name: &[Vec<u8>], zone: &[Vec<u8>]) -> Option<usize> {
    name::is_label_suffix(name, zone).then(|| name.len() - zone.len())
}
