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

    pub fn to_wire(&self) -> Result<Vec<u8>, ParseNameError> {
        super::labels_to_wire(self.0.split('.'))
    }
}

/// Decodes the stored form, so a row column can hold a zone name directly.
impl From<String> for ZoneName {
    fn from(value: String) -> Self {
        Self::from_row(&value)
    }
}

impl std::fmt::Display for ZoneName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
