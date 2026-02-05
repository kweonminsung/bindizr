use thiserror::Error;

use crate::{
    api::validation::ValidationError, config::error::ConfigError, database::error::DatabaseError,
    rndc::error::RndcError,
};

/// Top-level error type
#[derive(Debug, Error)]
pub enum BindizrError {
    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),

    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("RNDC error: {0}")]
    Rndc(#[from] RndcError),

    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Type alias
pub type Result<T> = std::result::Result<T, BindizrError>;
