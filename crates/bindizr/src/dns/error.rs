use bindizr_service::error::ServiceError;
use thiserror::Error;

/// Errors produced while handling zone transfers, NOTIFY, and DNS wire I/O.
#[derive(Debug, Error)]
pub(crate) enum XfrError {
    #[error("Zone not found: {0}")]
    ZoneNotFound(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("DNS protocol error: {0}")]
    ProtocolError(String),

    #[error("Invalid query: {0}")]
    InvalidQuery(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),
}

/// Protocol failures reported by the wire codec in `bindizr-core`.
impl From<String> for XfrError {
    fn from(message: String) -> Self {
        XfrError::ProtocolError(message)
    }
}

/// The DNS plane passes no caller, so a service failure here is never a
/// client fault — it surfaces as an infrastructure error.
impl From<ServiceError> for XfrError {
    fn from(e: ServiceError) -> Self {
        XfrError::DatabaseError(e.to_string())
    }
}
