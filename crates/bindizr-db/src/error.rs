use thiserror::Error;

/// Errors returned by database operations.
#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Query failed: {0}")]
    QueryFailed(String),

    /// A UNIQUE constraint rejected the statement. Kept distinct so callers
    /// can map lost check-then-insert races to a conflict instead of a
    /// generic internal error.
    #[error("Unique constraint violation: {0}")]
    UniqueViolation(String),

    /// A FOREIGN KEY constraint rejected the statement: the referenced row is
    /// gone, or the row is still referenced.
    #[error("Foreign key constraint violation: {0}")]
    ForeignKeyViolation(String),

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("Pool error: {0}")]
    PoolError(String),
}

impl DatabaseError {
    pub fn is_unique_violation(&self) -> bool {
        matches!(self, DatabaseError::UniqueViolation(_))
    }

    pub fn is_foreign_key_violation(&self) -> bool {
        matches!(self, DatabaseError::ForeignKeyViolation(_))
    }
}

impl From<sqlx::Error> for DatabaseError {
    fn from(err: sqlx::Error) -> Self {
        match &err {
            sqlx::Error::PoolTimedOut => {
                return DatabaseError::PoolError("Pool timed out".to_string());
            }
            sqlx::Error::Database(db_err) => match db_err.kind() {
                sqlx::error::ErrorKind::UniqueViolation => {
                    return DatabaseError::UniqueViolation(err.to_string());
                }
                sqlx::error::ErrorKind::ForeignKeyViolation => {
                    return DatabaseError::ForeignKeyViolation(err.to_string());
                }
                _ => {}
            },
            _ => {}
        }

        DatabaseError::QueryFailed(err.to_string())
    }
}
