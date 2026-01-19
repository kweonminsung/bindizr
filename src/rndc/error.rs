use thiserror::Error;

/// TODO: RNDC-related errors
#[allow(dead_code)]
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
