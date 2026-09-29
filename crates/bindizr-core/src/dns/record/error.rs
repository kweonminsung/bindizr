//! Why a stored record value could not be parsed, validated, or encoded.

use thiserror::Error;

use super::naptr::NaptrRegexpError;
use crate::{dns::name::ParseNameError, model::record::RecordType};

/// A record value that is not what its type's presentation form spells. The
/// text names the field, so the message stands on its own beside the value.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseRecordValueError {
    #[error("{field} must be between 0 and 65535")]
    OutOfRange { field: &'static str },
    #[error("{field} must be an unsigned 8-bit integer: {value}")]
    NotU8 { field: &'static str, value: String },
    #[error("{field} must be an unsigned 16-bit integer: {value}")]
    NotU16 { field: &'static str, value: String },
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    #[error("{field} must be an even number of hex digits")]
    OddHexLength { field: &'static str },
    #[error("{field} must be hex")]
    NotHex { field: &'static str },
    #[error("{field} must be a quoted string: {input}")]
    NotQuoted { field: &'static str, input: String },
    #[error("{field} must be valid UTF-8")]
    NotUtf8 { field: &'static str },
    #[error("{field} contains an invalid \\DDD escape")]
    InvalidEscape { field: &'static str },
    #[error("{field} ends in a dangling escape")]
    DanglingEscape { field: &'static str },
    #[error("{field} has an unterminated quote")]
    UnterminatedQuote { field: &'static str },
    #[error("{field} must be 255 bytes or less")]
    CharStringTooLong { field: &'static str },
    #[error("{field} must not contain whitespace or control characters")]
    Whitespace { field: &'static str },
    #[error("{field} must not be the root zone")]
    RootZone { field: &'static str },
    #[error("{field} {source}")]
    Name {
        field: &'static str,
        #[source]
        source: ParseNameError,
    },
    #[error("A record value must be a valid IPv4 address: {value}")]
    Ipv4 { value: String },
    #[error("AAAA record value must be a valid IPv6 address: {value}")]
    Ipv6 { value: String },
    #[error(
        "MX record value must be the target host '<target>', with the priority in the priority field: {value}"
    )]
    MxShape { value: String },
    #[error("Null MX record target '.' must use priority 0")]
    NullMxPriority,
    #[error(
        "SRV record value must be '<weight> <port> <target>', with the priority in the priority field: {value}"
    )]
    SrvShape { value: String },
    #[error("CAA record value must be '<flags> <tag> <value>': {value}")]
    CaaShape { value: String },
    #[error("CAA tag must be 1-15 alphanumeric characters: {tag}")]
    CaaTag { tag: String },
    #[error("CAA value must not be empty")]
    CaaValueEmpty,
    #[error("CAA value must not contain control characters")]
    CaaValueControl,
    #[error("CAA value must be at most {max} bytes, got {len}")]
    CaaValueTooLong { max: usize, len: usize },
    #[error("DS record value must be '<key tag> <algorithm> <digest type> <digest>': {value}")]
    DsShape { value: String },
    #[error("DS digest type {digest_type} takes a {expected}-byte digest, got {len}")]
    DsDigestLength {
        digest_type: u8,
        expected: usize,
        len: usize,
    },
    #[error("DS digest must be at most {max} bytes, got {len}")]
    DsDigestTooLong { max: usize, len: usize },
    #[error("SSHFP record value must be '<algorithm> <fingerprint type> <fingerprint>': {value}")]
    SshfpShape { value: String },
    #[error(
        "SSHFP fingerprint type {fingerprint_type} takes a {expected}-byte fingerprint, got {len}"
    )]
    SshfpFingerprintLength {
        fingerprint_type: u8,
        expected: usize,
        len: usize,
    },
    #[error("SSHFP fingerprint must be at most {max} bytes, got {len}")]
    SshfpFingerprintTooLong { max: usize, len: usize },
    #[error(
        "TLSA record value must be '<usage> <selector> <matching type> <certificate data>': {value}"
    )]
    TlsaShape { value: String },
    #[error("TLSA matching type {matching_type} takes {expected}-byte certificate data, got {len}")]
    TlsaDataLength {
        matching_type: u8,
        expected: usize,
        len: usize,
    },
    #[error("TLSA certificate data must be at most {max} bytes, got {len}")]
    TlsaDataTooLong { max: usize, len: usize },
    #[error("TXT RDATA is not a valid character-string sequence")]
    TxtRdata,
    #[error("TXT record must contain at least one character-string")]
    TxtNoCharString,
    #[error("TXT record data must be at most {max} bytes, got {len}")]
    TxtTooLong { max: usize, len: usize },
    #[error("TXT character-strings must be separated by spaces")]
    TxtUnseparated,
    #[error("TXT value contains a dangling escape")]
    TxtDanglingEscape,
    #[error("TXT value contains an unterminated quote")]
    TxtUnterminatedQuote,
    #[error(
        "NAPTR record value must be '<order> <preference> \"<flags>\" \"<services>\" \"<regexp>\" <replacement>': {value}"
    )]
    NaptrShape { value: String },
    #[error("NAPTR record value ends before {field}")]
    NaptrEndsBefore { field: &'static str },
    #[error("NAPTR record replacement must be '.' when the regexp is set (RFC 3403, Section 4.1)")]
    NaptrReplacementWithRegexp,
    #[error(transparent)]
    NaptrRegexp(#[from] NaptrRegexpError),
    #[error("{record_type} records do not take a priority")]
    PriorityNotTaken { record_type: RecordType },
    #[error("stored TXT value is not in presentation form: {value}")]
    StoredTxtNotPresentation { value: String },
}
