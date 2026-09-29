//! Errors from parsing and encoding the domain-name types.

use thiserror::Error;

use super::{MAX_DNS_LABEL_LEN, MAX_DOMAIN_LEN};

/// Why a name could not be parsed. Callers phrase these for their own layer.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseNameError {
    #[error("must not be empty")]
    Empty,
    #[error("must not contain whitespace or control characters")]
    Whitespace,
    #[error("must be {MAX_DOMAIN_LEN} bytes or fewer")]
    TooLong,
    #[error("must not contain empty labels")]
    EmptyLabel,
    #[error("labels must be {MAX_DNS_LABEL_LEN} bytes or fewer")]
    LabelTooLong,
    /// The LDH charset rule, which applies to zone names but not owner names.
    #[error("labels must contain only {}", if *underscore_allowed { "ASCII letters, digits, hyphens, or underscores" } else { "ASCII letters, digits, or hyphens" })]
    LabelCharset { underscore_allowed: bool },
    #[error("labels must not start or end with hyphens")]
    LabelHyphen,
    /// A `\` with nothing after it (RFC 1035, Section 5.1).
    #[error("ends with an incomplete escape")]
    DanglingEscape,
    /// A `\DDD` that is not three decimal digits, or is above 255.
    #[error("contains an invalid escape")]
    InvalidEscape,
    /// A label may hold any octet (RFC 2181, Section 11); bindizr holds names
    /// to ASCII text, an internationalized label as its `xn--` A-label.
    #[error("must be printable ASCII; spell an internationalized label in punycode (xn--)")]
    NonAscii,
    #[error("is outside the zone")]
    OutsideZone,
}

/// A presentation-form name that could not become wire labels.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("Invalid domain name '{name}': {source}")]
pub struct EncodeNameError {
    pub name: String,
    #[source]
    pub source: ParseNameError,
}
