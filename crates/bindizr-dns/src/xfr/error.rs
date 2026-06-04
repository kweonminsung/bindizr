use thiserror::Error;

#[derive(Debug, Error)]
pub enum XfrError {
    #[error("Zone not found: {0}")]
    ZoneNotFound(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("DNS protocol error: {0}")]
    ProtocolError(String),

    #[error("NOTIFY failed: {0}")]
    NotifyFailed(String),

    #[error("Invalid query: {0}")]
    InvalidQuery(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),
}
