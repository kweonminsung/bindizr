use thiserror::Error;

/// Configuration-related errors
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Configuration not found: {0}")]
    NotFound(String),

    #[error("Invalid configuration value: {0}")]
    InvalidValue(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Missing required configuration: {0}")]
    MissingRequired(String),
}
