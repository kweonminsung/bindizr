use bindizr_core::dns::{ConvertSerialError, Serial, message::EncodeMessageError};
use bindizr_service::error::ServiceError;
use thiserror::Error;

/// Causes of DNS listener, message I/O, and query handling failures.
#[derive(Debug, Error)]
pub(crate) enum DnsError {
    /// No enabled zone carries the name: answered NOTAUTH.
    #[error("not authoritative for zone: {0}")]
    NotAuth(String),

    /// The key that signed the request holds no grant over the zone whole.
    #[error("transfer refused: {0}")]
    Refused(String),

    #[error("service error: {0}")]
    Service(#[from] ServiceError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DNS protocol error: {0}")]
    Protocol(#[from] EncodeMessageError),

    #[error("DNS protocol error: {0}")]
    Serial(#[from] ConvertSerialError),

    /// The connection closed before a message began.
    #[error("connection closed")]
    PeerClosed,

    #[error("connection slots are closed: {0}")]
    ConnectionSlotsClosed(#[from] tokio::sync::AcquireError),

    /// The client read nothing for the whole write timeout.
    #[error("the client read nothing for {secs} seconds")]
    WriteTimeout { secs: u64 },

    /// A TCP frame that ended before its two-octet length prefix did.
    #[error("DNS protocol error: incomplete DNS TCP length prefix")]
    IncompletePrefix,

    /// A TCP frame shorter than its length prefix announced.
    #[error("DNS protocol error: incomplete DNS TCP message: expected {expected} bytes")]
    IncompleteMessage { expected: usize },

    /// An IXFR whose version rows do not cover a serial the journal names.
    #[error("DNS protocol error: missing {which} SOA version for serial {serial}")]
    MissingVersion { which: &'static str, serial: Serial },

    #[error("invalid query: {0}")]
    InvalidQuery(String),

    #[error("failed to build NSUPDATE response")]
    BuildNsupdateResponse,
}
