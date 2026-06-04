use thiserror::Error;

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Query failed: {0}")]
    QueryFailed(String),

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("Pool error: {0}")]
    PoolError(String),
}

impl From<sqlx::Error> for DatabaseError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::PoolTimedOut => DatabaseError::PoolError("Pool timed out".to_string()),
            _ => DatabaseError::QueryFailed(err.to_string()),
        }
    }
}
