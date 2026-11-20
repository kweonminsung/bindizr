//! Errors from parsing and encoding the domain-name types.

use thiserror::Error;

use crate::dns::LibraryError;
use crate::dns::name::{MAX_DNS_LABEL_LEN, MAX_DOMAIN_LEN};

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
    /// A `\` with nothing after it (RFC 1035, Section 5.1).
    #[error("ends with an incomplete escape")]
    DanglingEscape,
    /// A `\DDD` that is not three decimal digits, or is above 255.
    #[error("contains an invalid escape")]
    InvalidEscape,
    #[error("is outside the zone")]
    OutsideZone,
}

/// A typed name whose wire bytes the `domain` crate did not accept.
#[derive(Debug, Error)]
pub enum EncodeWireNameError {
    #[error(transparent)]
    Name(#[from] ParseNameError),
    #[error("invalid wire name: {0}")]
    Octets(#[source] LibraryError),
}

/// A presentation-form name that could not become wire labels.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid domain name '{name}': {source}")]
pub struct EncodeNameError {
    pub name: String,
    #[source]
    pub source: ParseNameError,
}
