use std::io;

use bindizr_core::dns::Serial;
use bindizr_core::dns::message::EncodeMessageError;
use bindizr_core::dns::nsupdate::BuildResponseError;
use bindizr_core::dns::tsig::TsigError;
use bindizr_service::error::ServiceError;
use thiserror::Error;
use tokio::sync::AcquireError;

/// Causes of DNS listener, message I/O, and query handling failures.
#[derive(Debug, Error)]
pub(crate) enum DnsError {
    /// No enabled zone carries the name: answered NOTAUTH.
    #[error("not authoritative for zone: {zone_name}")]
    NotAuth { zone_name: String },
    /// The key that signed the request holds no grant over the zone whole.
    #[error("transfer refused: {reason}")]
    Refused { reason: String },
    #[error("service error: {0}")]
    Service(#[from] ServiceError),
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("DNS protocol error: {0}")]
    Protocol(#[from] EncodeMessageError),
    #[error("TSIG error: {0}")]
    Tsig(#[from] TsigError),
    /// The connection closed before a message began.
    #[error("connection closed")]
    PeerClosed,
    #[error("connection slots are closed: {0}")]
    ConnectionSlotsClosed(#[from] AcquireError),
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
    #[error("invalid query: {reason}")]
    InvalidQuery { reason: String },
    #[error("failed to build NSUPDATE response: {0}")]
    BuildNsupdateResponse(#[from] BuildResponseError),
}
