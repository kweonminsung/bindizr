//! A record's owner name, held as decoded labels.

use super::{
    MAX_DNS_LABEL_LEN, MAX_DOMAIN_LEN, ParseNameError, ZoneName, has_whitespace_or_control,
};

/// A record's owner name as its decoded labels, relative to its zone. The
/// apex is the empty label list.
///
/// Presentation form is a rendering, not the representation: a `.` inside a
/// label is stored as data, so no spelling of a name can make one label read
/// as two. Labels are lowercased on construction, so the derived `Eq`/`Hash`
/// fold case (RFC 4343).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OwnerName(Vec<String>);

impl OwnerName {
    /// How the apex is spelled in presentation form and in rows.
    pub const APEX: &'static str = "@";

    pub fn apex() -> Self {
        Self(Vec::new())
    }

    pub fn is_apex(&self) -> bool {
        self.0.is_empty()
    }

    pub fn labels(&self) -> &[String] {
        &self.0
    }

    /// Parse client input — `@`, a relative name, or an absolute name inside
    /// `zone` — into the owner's labels. Labels are checked for wire safety
    /// only, since owner names carry the `_` labels a zone name may not.
    pub fn parse_in_zone(input: &str, zone: &ZoneName) -> Result<Self, ParseNameError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(ParseNameError::Empty);
        }
        if has_whitespace_or_control(trimmed) {
            return Err(ParseNameError::Whitespace);
        }
        if trimmed == Self::APEX {
            return Ok(Self::apex());
        }

        let absolute = trimmed.ends_with('.');
        let labels = decode_labels(trimmed.trim_end_matches('.'))?;
        if labels.is_empty() {
            return Err(ParseNameError::RootZone);
        }
        classify_labels(&labels)?;

        let zone_labels = zone.labels();
        let zone_labels = zone_labels.as_slice();
        // A relative name that happens to end in the zone was already absolute.
        match strip_zone_suffix(&labels, zone_labels) {
            Some(owner) => Ok(Self(owner)),
            None if absolute => Err(ParseNameError::OutsideZone),
            // Relative input is qualified by appending the zone, so it is
            // in-zone by construction; only its own length can fail.
            None => {
                classify_total_len(&labels, zone_labels)?;
                Ok(Self(labels))
            }
        }
    }

    /// Parse a name that is already absolute, so a name outside `zone` is an
    /// error instead of being qualified by appending the zone. Callers whose
    /// input carries no trailing dot (lookup form, wire owners) need this.
    pub fn parse_absolute_in_zone(input: &str, zone: &ZoneName) -> Result<Self, ParseNameError> {
        let trimmed = input.trim();
        if trimmed == Self::APEX {
            return Ok(Self::apex());
        }

        let labels = super::decode_name_labels(trimmed)?;
        strip_zone_suffix(&labels, zone.labels().as_slice())
            .map(Self)
            .ok_or(ParseNameError::OutsideZone)
    }

    /// Wrap a name already in stored form, as read from a row.
    pub fn from_row(value: &str) -> Self {
        if value == Self::APEX {
            return Self::apex();
        }

        match decode_labels(value.trim_end_matches('.')) {
            Ok(labels) => Self(labels),
            // Rows only ever hold what parse_in_zone wrote; a malformed one
            // becomes a single literal label rather than silently re-splitting.
            Err(_) => Self(vec![value.to_ascii_lowercase()]),
        }
    }

    /// The presentation form rows store: `@` at the apex, otherwise the labels
    /// joined with `.` and each label's own `.` and `\` escaped.
    pub fn to_stored(&self) -> String {
        if self.is_apex() {
            return Self::APEX.to_string();
        }

        self.0
            .iter()
            .map(|label| escape_label(label))
            .collect::<Vec<_>>()
            .join(".")
    }

    /// The absolute form within `zone`.
    pub fn to_fqdn(&self, zone: &ZoneName) -> String {
        if self.is_apex() {
            return zone.to_fqdn();
        }

        format!("{}.{}", self.to_stored(), zone.to_fqdn())
    }

    /// Whether this owner is `other` or sits under it, compared label by label.
    pub fn is_same_or_under(&self, other: &Self) -> bool {
        is_label_suffix(&self.0, &other.0)
    }
}

impl std::fmt::Display for OwnerName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_stored())
    }
}

/// Decode a presentation-form name into lowercase labels, resolving the `\X`
/// and `\DDD` escapes (RFC 1035, Section 5.1).
pub(super) fn decode_labels(name: &str) -> Result<Vec<String>, ParseNameError> {
    let mut labels = Vec::new();
    let mut label: Vec<u8> = Vec::new();
    let mut chars = name.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '.' => labels.push(finish_label(std::mem::take(&mut label))?),
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
                Some(_) => {
                    let escaped = chars.next().expect("peek returned a character");
                    let mut buf = [0u8; 4];
                    label.extend_from_slice(escaped.encode_utf8(&mut buf).as_bytes());
                }
            },
            c => {
                let mut buf = [0u8; 4];
                label.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }

    labels.push(finish_label(label)?);
    Ok(labels)
}

fn finish_label(label: Vec<u8>) -> Result<String, ParseNameError> {
    String::from_utf8(label)
        .map(|label| label.to_ascii_lowercase())
        .map_err(|_| ParseNameError::NonUtf8Label)
}

/// Inverse of [`decode_labels`] for one label: escape `.` and `\` so the label
/// survives a round trip as a single label.
pub(super) fn escape_label(label: &str) -> std::borrow::Cow<'_, str> {
    if !label.contains(['.', '\\']) {
        return std::borrow::Cow::Borrowed(label);
    }

    let mut escaped = String::with_capacity(label.len() + 1);
    for c in label.chars() {
        if c == '.' || c == '\\' {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    std::borrow::Cow::Owned(escaped)
}

fn classify_labels(labels: &[String]) -> Result<(), ParseNameError> {
    for label in labels {
        if label.is_empty() {
            return Err(ParseNameError::EmptyLabel);
        }
        if label.len() > MAX_DNS_LABEL_LEN {
            return Err(ParseNameError::LabelTooLong);
        }
    }
    Ok(())
}

/// The 253-byte limit, measured on the decoded octets the wire carries.
fn classify_total_len(owner: &[String], zone: &[String]) -> Result<(), ParseNameError> {
    let len: usize = owner.iter().chain(zone).map(|label| label.len() + 1).sum();
    if len > MAX_DOMAIN_LEN {
        return Err(ParseNameError::TooLong);
    }
    Ok(())
}

/// The labels left after removing `zone` from the end of `name`, or `None`
/// when `name` does not sit inside `zone`.
fn strip_zone_suffix(name: &[String], zone: &[String]) -> Option<Vec<String>> {
    is_label_suffix(name, zone).then(|| name[..name.len() - zone.len()].to_vec())
}

pub(super) fn is_label_suffix(name: &[String], suffix: &[String]) -> bool {
    name.len() >= suffix.len() && name[name.len() - suffix.len()..] == *suffix
}
