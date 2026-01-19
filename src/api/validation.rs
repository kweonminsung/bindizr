use thiserror::Error;

/// Validation-related errors
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[error("Constraint violation: {0}")]
    ConstraintViolation(String),
}
