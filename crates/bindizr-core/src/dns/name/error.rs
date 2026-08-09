//! Errors from parsing the domain-name types.

use super::{MAX_DNS_LABEL_LEN, MAX_DOMAIN_LEN};

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
