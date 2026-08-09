//! Parsed domain-name types. A value of either type is canonical by
//! construction — lowercase, trailing-dot-free, label-checked — so `==` and
//! `Hash` are DNS-correct without every call site remembering to fold case.

use super::{
    MAX_DNS_LABEL_LEN, MAX_DOMAIN_LEN, escape_presentation_label, has_whitespace_or_control,
    is_same_or_subdomain_fqdn, presentation_labels, to_fqdn, to_owner_fqdn, validate_domain_label,
};

/// Why a name could not be parsed. Callers phrase these for their own layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseNameError {
    Empty,
    RootZone,
    Whitespace,
    TooLong,
    EmptyLabel,
    LabelTooLong,
    /// Only the LDH charset rule, which applies to zone names but not owner names.
    InvalidLabel(String),
    DanglingEscape,
    OutsideZone,
}

impl std::fmt::Display for ParseNameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "must not be empty"),
            Self::RootZone => write!(f, "must not be the root zone"),
            Self::Whitespace => write!(f, "must not contain whitespace or control characters"),
            Self::TooLong => write!(f, "must be {} bytes or fewer", MAX_DOMAIN_LEN),
            Self::EmptyLabel => write!(f, "must not contain empty labels"),
            Self::LabelTooLong => write!(f, "labels must be {} bytes or fewer", MAX_DNS_LABEL_LEN),
            Self::InvalidLabel(detail) => write!(f, "{}", detail),
            Self::DanglingEscape => write!(f, "contains a dangling escape"),
            Self::OutsideZone => write!(f, "is outside the zone"),
        }
    }
}

impl std::error::Error for ParseNameError {}

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
            validate_domain_label(label, "name", false, ParseNameError::InvalidLabel)?;
        }

        Ok(Self(bare.to_ascii_lowercase()))
    }

    /// Wrap a name already in stored form, as read from a row.
    pub fn from_row(value: &str) -> Self {
        Self(value.trim_end_matches('.').to_ascii_lowercase())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The absolute form, with the trailing dot.
    pub fn to_fqdn(&self) -> String {
        to_fqdn(&self.0)
    }
}

impl std::fmt::Display for ZoneName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A record's owner name as rows encode it: `@` at the apex, otherwise a
/// lowercase name relative to its zone.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OwnerName(String);

impl OwnerName {
    /// The owner name of the zone apex.
    pub const APEX: &'static str = "@";

    pub fn apex() -> Self {
        Self(Self::APEX.to_string())
    }

    /// Parse client input — `@`, a relative name, or an absolute name inside
    /// `zone` — into the stored form. Labels are checked for wire safety only:
    /// owner names legitimately carry `_`-prefixed labels that a zone name may
    /// not.
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
        if trimmed.trim_end_matches('.').is_empty() {
            return Err(ParseNameError::RootZone);
        }

        let zone_fqdn = zone.to_fqdn();
        let candidate = to_owner_fqdn(trimmed, zone.as_str());
        validate_wire_labels(&candidate)?;

        // A relative name that happens to end in the zone was already absolute.
        if !is_same_or_subdomain_fqdn(&candidate.to_ascii_lowercase(), &zone_fqdn) {
            return Err(ParseNameError::OutsideZone);
        }

        super::to_encoded_owner_name(&candidate, zone.as_str())
            .map(Self)
            .ok_or(ParseNameError::OutsideZone)
    }

    /// Wrap a name already in stored form, as read from a row.
    pub fn from_row(value: &str) -> Self {
        Self(value.to_ascii_lowercase())
    }

    pub fn is_apex(&self) -> bool {
        self.0 == Self::APEX
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The absolute form within `zone`.
    pub fn to_fqdn(&self, zone: &ZoneName) -> String {
        to_owner_fqdn(&self.0, zone.as_str())
    }

    /// Prefix this owner name with `label`, escaping a dot inside it.
    pub fn prefixed(&self, label: &str) -> Self {
        let label = escape_presentation_label(label).to_ascii_lowercase();
        if self.is_apex() {
            Self(label)
        } else {
            Self(format!("{}.{}", label, self.0))
        }
    }
}

impl std::fmt::Display for OwnerName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The 253-byte and per-label limits, without the LDH charset rule.
fn validate_wire_labels(name: &str) -> Result<(), ParseNameError> {
    let bare = name.trim_end_matches('.');
    if bare.len() > MAX_DOMAIN_LEN {
        return Err(ParseNameError::TooLong);
    }

    for label in presentation_labels(bare).map_err(|_| ParseNameError::DanglingEscape)? {
        if label.is_empty() {
            return Err(ParseNameError::EmptyLabel);
        }
        if label.len() > MAX_DNS_LABEL_LEN {
            return Err(ParseNameError::LabelTooLong);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests;
