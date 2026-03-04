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

    #[error("Invalid query: {0}")]
    InvalidQuery(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Serial mismatch: client={0}, current={1}")]
    SerialMismatch(u32, u32),

    #[allow(dead_code)]
    #[error("No history available for IXFR")]
    NoHistoryAvailable,
}
