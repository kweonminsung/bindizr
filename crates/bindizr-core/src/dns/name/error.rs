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
    /// The LDH charset rule, which applies to zone names but not owner names.
    LabelCharset {
        underscore_allowed: bool,
    },
    LabelHyphen,
    /// bindizr stores names unescaped, so `\` is rejected rather than read as
    /// an escape (RFC 1035, Section 5.1).
    Escape,
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
            Self::LabelCharset { underscore_allowed } => write!(
                f,
                "labels must contain only {}",
                if *underscore_allowed {
                    "ASCII letters, digits, hyphens, or underscores"
                } else {
                    "ASCII letters, digits, or hyphens"
                }
            ),
            Self::LabelHyphen => write!(f, "labels must not start or end with hyphens"),
            Self::Escape => write!(f, "must not contain escapes"),
            Self::OutsideZone => write!(f, "is outside the zone"),
        }
    }
}

impl std::error::Error for ParseNameError {}
