use thiserror::Error;

/// TODO: Database-related errors
#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Query failed: {0}")]
    QueryFailed(String),

    #[error("Record not found: {0}")]
    NotFound(String),

    #[error("Record already exists: {0}")]
    AlreadyExists(String),

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("Migration failed: {0}")]
    MigrationFailed(String),

    #[error("Pool error: {0}")]
    PoolError(String),
}

impl From<sqlx::Error> for DatabaseError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => DatabaseError::NotFound("Row not found".to_string()),
            sqlx::Error::PoolTimedOut => DatabaseError::PoolError("Pool timed out".to_string()),
            _ => DatabaseError::QueryFailed(err.to_string()),
        }
    }
}
