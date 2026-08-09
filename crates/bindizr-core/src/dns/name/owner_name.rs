//! A record's owner name, canonical by construction.

use super::{
    ParseNameError, ZoneName, classify_wire_labels, escape_presentation_label,
    has_whitespace_or_control, is_same_or_subdomain_fqdn, to_encoded_owner_name, to_owner_fqdn,
};

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
        classify_wire_labels(&candidate)?;

        // A relative name that happens to end in the zone was already absolute.
        if !is_same_or_subdomain_fqdn(&candidate.to_ascii_lowercase(), &zone_fqdn) {
            return Err(ParseNameError::OutsideZone);
        }

        to_encoded_owner_name(&candidate, zone.as_str())
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
