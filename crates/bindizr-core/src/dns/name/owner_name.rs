//! A record's owner name, held as decoded labels.

use super::{MAX_DNS_LABEL_LEN, MAX_WIRE_NAME_LEN, ParseNameError, ZoneName};

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

    /// Check whether this owner names the zone apex.
    pub fn is_apex(&self) -> bool {
        self.0.is_empty()
    }

    /// Return the owner's decoded DNS labels.
    pub fn labels(&self) -> &[Vec<u8>] {
        &self.0
    }

    /// Parse `@`, relative names, or absolute names inside `zone` into octet labels.
    /// Validate wire lengths without imposing hostname character rules.
    pub fn parse_in_zone(input: &str, zone_name: &ZoneName) -> Result<Self, ParseNameError> {
        let trimmed = super::trim_presentation_name(input);

        if trimmed.trim_end_matches('.').is_empty() {
            return Err(ParseNameError::Empty);
        }
        if trimmed == Self::APEX {
            return Ok(Self::apex());
        }

        let (labels, absolute) = decode_name_labels(trimmed)?;
        let zone_labels = zone_name.labels();

        // A relative name that happens to end in the zone was already absolute.
        match relative_labels(&labels, &zone_labels) {
            Some(owner) => Ok(Self(owner)),
            None if absolute => Err(ParseNameError::OutsideZone),
            // Relative input grows by the zone it is qualified with, which is
            // what can push it past the length `decode_name_labels` checked.
            None => {
                classify_wire_len(&labels, &zone_labels)?;
                Ok(Self(labels))
            }
        }
    }

    /// Parse an absolute name inside `zone`, even without a trailing root dot.
    /// Relative client input belongs to [`Self::parse_in_zone`].
    pub fn parse_absolute_in_zone(
        input: &str,
        zone_name: &ZoneName,
    ) -> Result<Self, ParseNameError> {
        let trimmed = super::trim_presentation_name(input);

        if trimmed == Self::APEX {
            return Ok(Self::apex());
        }

        let (labels, _) = decode_name_labels(trimmed)?;

        relative_labels(&labels, zone_name.labels().as_slice())
            .map(Self)
            .ok_or(ParseNameError::OutsideZone)
    }

    /// Wrap a name already in stored form, as read from a row.
    pub fn from_row(value: &str) -> Self {
        if value.is_empty() {
            return Self::apex();
        }

        match decode_name_labels(value) {
            Ok((labels, _)) => Self(labels),
            // An externally corrupted row becomes one literal label; splitting it
            // would invent a different name.
            Err(error) => {
                log::error!(
                    "undecodable owner name in a record row: {} ({})",
                    value,
                    error
                );
                Self(vec![value.as_bytes().to_ascii_lowercase()])
            }
        }
    }

    /// The form rows store: empty at the apex, so no label can collide with it,
    /// otherwise the escaped labels joined with `.`.
    pub fn to_stored(&self) -> String {
        if self.is_apex() {
            return String::new();
        }

        self.to_presentation()
    }

    /// The wire form within `zone`: this owner's labels, the zone's, then the
    /// root.
    pub fn to_wire(&self, zone_name: &ZoneName) -> Result<Vec<u8>, ParseNameError> {
        let zone_labels = zone_name.labels();
        super::labels_to_wire(
            self.0
                .iter()
                .map(Vec::as_slice)
                .chain(zone_labels.iter().map(Vec::as_slice)),
        )
    }

    /// The absolute form within `zone`.
    pub fn to_fqdn(&self, zone_name: &ZoneName) -> String {
        if self.is_apex() {
            return zone_name.to_fqdn();
        }

        format!("{}.{}", self.to_presentation(), zone_name.to_fqdn())
    }

    /// This owner's labels in presentation form, with the required escapes.
    fn to_presentation(&self) -> String {
        super::labels_to_presentation(&self.0)
    }

    /// Whether this owner is `other` or sits under it, compared label by label.
    pub fn is_same_or_under(&self, other: &Self) -> bool {
        is_label_suffix(&self.0, &other.0)
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

    /// Check whether the SQL type can store this value.
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
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        self.to_stored().encode_by_ref(buffer)
    }
}

/// The read half: the column holds the row form, so decoding never fails.
impl<'r, DB: sqlx::Database> sqlx::Decode<'r, DB> for OwnerName
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

/// Presentation form, as input spells it: `@` at the apex; rows take
/// [`OwnerName::to_stored`].
impl std::fmt::Display for OwnerName {
    /// Write the owner name in its display form.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_apex() {
            return f.write_str(Self::APEX);
        }
        f.write_str(&self.to_presentation())
    }
}

/// Decode octet labels and enforce wire lengths; return whether the root was present.
/// An escaped final dot (`a\.`) is label data, not the root.
pub fn decode_name_labels(name: &str) -> Result<(Vec<Vec<u8>>, bool), ParseNameError> {
    let (mut labels, absolute) = decode_preserved_labels(name)?;
    for label in &mut labels {
        label.make_ascii_lowercase();
    }
    Ok((labels, absolute))
}

/// Decode octet labels without changing case, for RDATA storage and wire output.
pub(crate) fn decode_preserved_labels(name: &str) -> Result<(Vec<Vec<u8>>, bool), ParseNameError> {
    let mut labels = decode_labels(name)?;

    // The root's empty label terminates a name rather than being one. Deciding
    // that here keeps an escaped trailing dot (`a\.`) from reading as the root.
    let absolute = labels.len() > 1 && labels[labels.len() - 1].is_empty();

    if absolute {
        labels.pop();
    }

    for label in &labels {
        classify_owner_label(label)?;
    }

    classify_wire_len(&labels, &[])?;

    Ok((labels, absolute))
}

/// Decode a presentation-form name into octet labels, resolving the `\X`
/// and `\DDD` escapes (RFC 1035, Section 5.1).
pub(crate) fn decode_labels(name: &str) -> Result<Vec<Vec<u8>>, ParseNameError> {
    let mut labels = Vec::new();
    let mut label: Vec<u8> = Vec::new();
    let mut chars = name.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            c if c.is_ascii_whitespace() || c.is_ascii_control() => {
                return Err(ParseNameError::Whitespace);
            }
            '.' => labels.push(std::mem::take(&mut label)),
            '\\' => match chars.peek() {
                None => return Err(ParseNameError::DanglingEscape),
                Some(d) if d.is_ascii_digit() => {
                    let mut octet: u32 = 0;

                    for _ in 0..3 {
                        let digit = chars
                            .next()
                            .and_then(|c| c.to_digit(10))
                            .ok_or(ParseNameError::InvalidEscape)?;
                        octet = octet * 10 + digit;
                    }

                    label.push(u8::try_from(octet).map_err(|_| ParseNameError::InvalidEscape)?);
                }
                Some(&escaped) => {
                    chars.next();
                    let mut buffer = [0u8; 4];
                    label.extend_from_slice(escaped.encode_utf8(&mut buffer).as_bytes());
                }
            },
            c => {
                let mut buffer = [0u8; 4];
                label.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }

    labels.push(label);

    Ok(labels)
}

/// Validate only the DNS label length (RFC 2181, Section 11).
fn classify_owner_label(label: &[u8]) -> Result<(), ParseNameError> {
    if label.is_empty() {
        return Err(ParseNameError::EmptyLabel);
    }
    if label.len() > MAX_DNS_LABEL_LEN {
        return Err(ParseNameError::LabelTooLong);
    }

    Ok(())
}

/// Check the DNS wire-length limit in RFC 1035, Section 2.3.4, including each label's length
/// octet and the root terminator.
fn classify_wire_len(owner: &[Vec<u8>], zone: &[Vec<u8>]) -> Result<(), ParseNameError> {
    let wire_len: usize = owner
        .iter()
        .chain(zone)
        .map(|label| label.len() + 1)
        .sum::<usize>()
        + 1;

    if wire_len > MAX_WIRE_NAME_LEN {
        return Err(ParseNameError::TooLong);
    }

    Ok(())
}

/// Escape separators, backslashes, the origin marker `@`, and master-file
/// metacharacters (RFC 1035, Section 5.1).
const ESCAPED_IN_LABEL: &[u8] = b".\\@;()\"$";

/// Escape a label without changing its octets; dots use decimal escapes so
/// a stored dot is always a label boundary (RFC 1035, Section 5.1).
pub(crate) fn escape_label(label: &[u8]) -> String {
    let mut escaped = String::with_capacity(label.len());

    for &byte in label {
        match byte {
            b'.' => escaped.push_str(r"\046"),
            0x21..=0x7e if !ESCAPED_IN_LABEL.contains(&byte) => escaped.push(char::from(byte)),
            byte if ESCAPED_IN_LABEL.contains(&byte) => {
                escaped.push('\\');
                escaped.push(char::from(byte));
            }
            byte => escaped.push_str(&format!("\\{byte:03}")),
        }
    }

    escaped
}

/// Whether `suffix` is a label-wise suffix of `name` (the same name or under it).
pub fn is_label_suffix(name: &[Vec<u8>], suffix: &[Vec<u8>]) -> bool {
    name.len() >= suffix.len() && name[name.len() - suffix.len()..] == *suffix
}

/// The labels left after removing `zone` from the end of `name`, or `None`
/// when `name` does not sit inside `zone`.
fn relative_labels(name: &[Vec<u8>], zone: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    is_label_suffix(name, zone).then(|| name[..name.len() - zone.len()].to_vec())
}
