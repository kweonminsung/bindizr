use thiserror::Error;

/// TODO: Configuration-related errors
#[allow(dead_code)]
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
