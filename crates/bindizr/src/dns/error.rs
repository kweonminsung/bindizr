use bindizr_core::dns::{ConvertSerialError, Serial, message::EncodeMessageError};
use bindizr_service::error::ServiceError;
use thiserror::Error;

/// Errors produced while handling zone transfers, NOTIFY, and DNS wire I/O.
#[derive(Debug, Error)]
pub(crate) enum XfrError {
    /// No enabled zone carries the name: answered NOTAUTH.
    #[error("Not authoritative for zone: {0}")]
    NotAuth(String),

    /// The key that signed the request holds no grant over the zone whole.
    #[error("Transfer refused: {0}")]
    Refused(String),

    /// The DNS plane passes no caller, so a service failure here is never a
    /// client fault: it surfaces as an infrastructure error.
    #[error("Database error: {0}")]
    Service(#[from] ServiceError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DNS protocol error: {0}")]
    Protocol(#[from] EncodeMessageError),

    #[error("DNS protocol error: {0}")]
    Serial(#[from] ConvertSerialError),

    /// A TCP frame that ended before its two-octet length prefix did.
    #[error("DNS protocol error: Incomplete DNS TCP length prefix")]
    IncompletePrefix,

    /// A TCP frame shorter than its length prefix announced.
    #[error("DNS protocol error: Incomplete DNS TCP message: expected {expected} bytes")]
    IncompleteMessage { expected: usize },

    /// An IXFR whose version rows do not cover a serial the journal names.
    #[error("DNS protocol error: Missing {which} SOA version for serial {serial}")]
    MissingVersion { which: &'static str, serial: Serial },

    #[error("Invalid query: {0}")]
    InvalidQuery(String),
}
