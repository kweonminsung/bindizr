use std::path::PathBuf;

use thiserror::Error;

/// A failure of the database layer, with the sqlx or I/O error that caused
/// it kept as its source.
#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Query failed: {0}")]
    QueryFailed(#[source] sqlx::Error),

    /// A UNIQUE constraint rejected the statement. Kept distinct so callers
    /// can map lost check-then-insert races to a conflict instead of a
    /// generic internal error.
    #[error("Unique constraint violation: {0}")]
    UniqueViolation(#[source] sqlx::Error),

    /// A FOREIGN KEY constraint rejected the statement: the referenced row is
    /// gone, or the row is still referenced.
    #[error("Foreign key constraint violation: {0}")]
    ForeignKeyViolation(#[source] sqlx::Error),

    #[error("Transaction failed: {0}")]
    TransactionFailed(#[source] sqlx::Error),

    #[error("Pool timed out")]
    PoolTimedOut,

    /// Each names the setting an operator would fix.
    #[error("MySQL connection failed (check database.mysql.url): {0}")]
    MySqlConnect(#[source] sqlx::Error),

    #[error("PostgreSQL connection failed (check database.postgresql.url): {0}")]
    PostgresConnect(#[source] sqlx::Error),

    #[error("SQLite open failed (check database.sqlite.file_path): {0}")]
    SqliteOpen(#[source] sqlx::Error),

    #[error("Invalid SQLite file path: {0}")]
    InvalidSqlitePath(#[source] sqlx::Error),

    #[error("File path cannot be empty")]
    EmptySqlitePath,

    #[error("Failed to create the SQLite directory '{}' (check database.sqlite.file_path): {source}", path.display())]
    CreateSqliteDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl DatabaseError {
    /// Check whether the database error reports a duplicate unique value.
    pub fn is_unique_violation(&self) -> bool {
        matches!(self, DatabaseError::UniqueViolation(_))
    }

    /// Check whether the database error reports a foreign-key violation.
    pub fn is_foreign_key_violation(&self) -> bool {
        matches!(self, DatabaseError::ForeignKeyViolation(_))
    }
}

impl From<sqlx::Error> for DatabaseError {
    /// Classify a sqlx error by the constraint it reports, keeping it as the
    /// source.
    fn from(err: sqlx::Error) -> Self {
        match &err {
            sqlx::Error::PoolTimedOut => DatabaseError::PoolTimedOut,
            sqlx::Error::Database(db_err) => match db_err.kind() {
                sqlx::error::ErrorKind::UniqueViolation => DatabaseError::UniqueViolation(err),
                sqlx::error::ErrorKind::ForeignKeyViolation => {
                    DatabaseError::ForeignKeyViolation(err)
                }
                _ => DatabaseError::QueryFailed(err),
            },
            _ => DatabaseError::QueryFailed(err),
        }
    }
}
