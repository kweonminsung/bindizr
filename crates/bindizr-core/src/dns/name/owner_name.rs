//! A record's owner name, held as decoded labels.

use super::{
    MAX_DNS_LABEL_LEN, MAX_DOMAIN_LEN, ParseNameError, ZoneName, has_whitespace_or_control,
};

/// A record's owner name as its decoded labels, relative to its zone; the apex
/// is the empty label list. A `.` inside a label is data, so no spelling can
/// make one label read as two. Labels are lowercased on construction, so the
/// derived `Eq`/`Hash` fold case (RFC 4343).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OwnerName(Vec<String>);

impl OwnerName {
    /// How the apex is spelled in input and in presentation. Rows hold it out
    /// of band, as the empty string.
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
        if trimmed.trim_end_matches('.').is_empty() {
            return Err(ParseNameError::Empty);
        }
        if trimmed == Self::APEX {
            return Ok(Self::apex());
        }

        let (labels, absolute) = decode_name_labels(trimmed)?;
        let zone_labels = zone.labels();

        // A relative name that happens to end in the zone was already absolute.
        match strip_zone_suffix(&labels, &zone_labels) {
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

    /// Parse a name that is already absolute, so a name outside `zone` is an
    /// error instead of being qualified by appending the zone. Callers whose
    /// input carries no trailing dot (lookup form, wire owners) need this.
    pub fn parse_absolute_in_zone(input: &str, zone: &ZoneName) -> Result<Self, ParseNameError> {
        let trimmed = input.trim();
        if trimmed == Self::APEX {
            return Ok(Self::apex());
        }

        let (labels, _) = decode_name_labels(trimmed)?;
        strip_zone_suffix(&labels, zone.labels().as_slice())
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
            // Only parse_in_zone writes these rows, so a decode failure means
            // the row was edited outside bindizr; one literal label matches
            // nothing rather than re-splitting into a name it never was.
            Err(e) => {
                crate::log_error!("undecodable owner name in a record row: {} ({})", value, e);
                Self(vec![value.to_ascii_lowercase()])
            }
        }
    }

    /// The form rows store: empty at the apex, so no label can collide with it,
    /// otherwise the escaped labels joined with `.`.
    pub fn to_stored(&self) -> String {
        if self.is_apex() {
            return String::new();
        }

        self.render_labels()
    }

    /// The wire form within `zone`: this owner's labels, the zone's, then the
    /// root.
    pub fn to_wire(&self, zone: &ZoneName) -> Result<Vec<u8>, ParseNameError> {
        let zone_labels = zone.labels();
        super::labels_to_wire(
            self.0
                .iter()
                .map(String::as_str)
                .chain(zone_labels.iter().map(String::as_str)),
        )
    }

    /// The absolute form within `zone`.
    pub fn to_fqdn(&self, zone: &ZoneName) -> String {
        if self.is_apex() {
            return zone.to_fqdn();
        }

        format!("{}.{}", self.render_labels(), zone.to_fqdn())
    }

    fn render_labels(&self) -> String {
        // Most owners are one label, which needs no join buffer.
        if let [label] = self.0.as_slice() {
            return escape_label(label).into_owned();
        }
        self.0
            .iter()
            .map(|label| escape_label(label))
            .collect::<Vec<_>>()
            .join(".")
    }

    /// Whether this owner is `other` or sits under it, compared label by label.
    pub fn is_same_or_under(&self, other: &Self) -> bool {
        is_label_suffix(&self.0, &other.0)
    }
}

/// Decodes the stored form, so a row column can hold an owner name directly.
impl From<String> for OwnerName {
    fn from(value: String) -> Self {
        Self::from_row(&value)
    }
}

/// The write half: binding renders [`OwnerName::to_stored`], so a query cannot
/// reach a column through [`std::fmt::Display`], whose apex is `@`.
impl<DB: sqlx::Database> sqlx::Type<DB> for OwnerName
where
    String: sqlx::Type<DB>,
{
    fn type_info() -> DB::TypeInfo {
        <String as sqlx::Type<DB>>::type_info()
    }

    fn compatible(ty: &DB::TypeInfo) -> bool {
        <String as sqlx::Type<DB>>::compatible(ty)
    }
}

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for OwnerName
where
    String: sqlx::Encode<'q, DB>,
{
    fn encode_by_ref(
        &self,
        buf: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        self.to_stored().encode_by_ref(buf)
    }
}

/// Presentation form, as input spells it: `@` at the apex; rows take
/// [`OwnerName::to_stored`].
impl std::fmt::Display for OwnerName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_apex() {
            return f.write_str(Self::APEX);
        }
        f.write_str(&self.render_labels())
    }
}

/// Decode a name into its labels, applying the wire length limits but not the
/// LDH charset rule only zone names take. The flag is whether the name ended at
/// the root — no string test can tell: `a\.` ends with a dot that is data.
pub fn decode_name_labels(name: &str) -> Result<(Vec<String>, bool), ParseNameError> {
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

/// Decode a presentation-form name into lowercase labels, resolving the `\X`
/// and `\DDD` escapes (RFC 1035, Section 5.1).
pub fn decode_labels(name: &str) -> Result<Vec<String>, ParseNameError> {
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
        .map(|mut label| {
            label.make_ascii_lowercase();
            label
        })
        .map_err(|_| ParseNameError::NonUtf8Label)
}

/// What every owner label must satisfy, whichever constructor produced it.
/// Not LDH — owner names carry `_` and `*` — so it rejects only what input
/// cannot spell back: whitespace and control octets, literal or via `\DDD`.
fn classify_owner_label(label: &str) -> Result<(), ParseNameError> {
    if label.is_empty() {
        return Err(ParseNameError::EmptyLabel);
    }
    if label.len() > MAX_DNS_LABEL_LEN {
        return Err(ParseNameError::LabelTooLong);
    }
    if has_whitespace_or_control(label) {
        return Err(ParseNameError::Whitespace);
    }
    Ok(())
}

/// The RFC 1035, Section 2.3.4 limit, measured on the wire form: one length
/// octet per label plus the root's terminating zero.
fn classify_wire_len(owner: &[String], zone: &[String]) -> Result<(), ParseNameError> {
    let wire_len: usize = owner
        .iter()
        .chain(zone)
        .map(|label| label.len() + 1)
        .sum::<usize>()
        + 1;
    if wire_len > MAX_DOMAIN_LEN + 2 {
        return Err(ParseNameError::TooLong);
    }
    Ok(())
}

/// What a label escapes to survive its own presentation form: the separator
/// and escape themselves, the `@` that RFC 1035, Section 5.1 fixes as the
/// origin, and the master-file metacharacters that would end the owner field.
const ESCAPED_IN_LABEL: [char; 8] = ['.', '\\', '@', ';', '(', ')', '"', '$'];

/// Inverse of [`decode_labels`] for one label.
pub fn escape_label(label: &str) -> std::borrow::Cow<'_, str> {
    if !label.contains(ESCAPED_IN_LABEL) {
        return std::borrow::Cow::Borrowed(label);
    }

    let mut escaped = String::with_capacity(label.len() + 1);
    for c in label.chars() {
        if ESCAPED_IN_LABEL.contains(&c) {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    std::borrow::Cow::Owned(escaped)
}

/// Whether `suffix` is a label-wise suffix of `name` (the same name or under it).
pub fn is_label_suffix(name: &[String], suffix: &[String]) -> bool {
    name.len() >= suffix.len() && name[name.len() - suffix.len()..] == *suffix
}

/// The labels left after removing `zone` from the end of `name`, or `None`
/// when `name` does not sit inside `zone`.
fn strip_zone_suffix(name: &[String], zone: &[String]) -> Option<Vec<String>> {
    is_label_suffix(name, zone).then(|| name[..name.len() - zone.len()].to_vec())
}
