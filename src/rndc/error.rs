use thiserror::Error;

/// RNDC-related errors
#[derive(Debug, Error)]
pub enum RndcError {
    #[error("Command execution failed: {0}")]
    CommandFailed(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Panic occurred: {0}")]
    PanicOccurred(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),
}
