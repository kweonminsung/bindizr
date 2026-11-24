use std::io;
use std::num::TryFromIntError;
use std::path::PathBuf;

use sqlx::error::ErrorKind;
use thiserror::Error;

/// A failure of the database layer, with the sqlx or I/O error that caused
/// it kept as its source.
#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("query failed: {0}")]
    QueryFailed(#[source] sqlx::Error),
    /// A UNIQUE violation, kept distinct so lost insert races can report conflicts.
    #[error("unique constraint violation: {0}")]
    UniqueViolation(#[source] sqlx::Error),
    /// A FOREIGN KEY constraint rejected the statement: the referenced row is
    /// gone, or the row is still referenced.
    #[error("foreign key constraint violation: {0}")]
    ForeignKeyViolation(#[source] sqlx::Error),
    #[error("transaction failed: {0}")]
    TransactionFailed(#[source] sqlx::Error),
    /// A SQLite rowid past the 32-bit range ids are carried in.
    #[error("row id {id} exceeds the 32-bit id range")]
    IdOutOfRange {
        id: i64,
        #[source]
        source: TryFromIntError,
    },
    #[error("pool timed out")]
    PoolTimedOut(#[source] sqlx::Error),
    /// Each names the setting an operator would fix.
    #[error("MySQL connection failed (check database.mysql.url): {0}")]
    MySqlConnect(#[source] sqlx::Error),
    #[error("PostgreSQL connection failed (check database.postgresql.url): {0}")]
    PostgresConnect(#[source] sqlx::Error),
    #[error("SQLite open failed (check database.sqlite.file_path): {0}")]
    SqliteOpen(#[source] sqlx::Error),
    #[error("invalid SQLite file path: {0}")]
    InvalidSqlitePath(#[source] sqlx::Error),
    #[error("file path cannot be empty")]
    EmptySqlitePath,
    #[error("failed to create the SQLite directory '{}' (check database.sqlite.file_path): {source}", path.display())]
    CreateSqliteDir {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl DatabaseError {
    /// Return whether the database error reports a duplicate unique value.
    pub fn is_unique_violation(&self) -> bool {
        matches!(self, Self::UniqueViolation(_))
    }

    /// Return whether the database error reports a foreign-key violation.
    pub fn is_foreign_key_violation(&self) -> bool {
        matches!(self, Self::ForeignKeyViolation(_))
    }
}

impl From<sqlx::Error> for DatabaseError {
    /// Classify a sqlx error by the constraint it reports, keeping it as the
    /// source.
    fn from(error: sqlx::Error) -> Self {
        match &error {
            sqlx::Error::PoolTimedOut => Self::PoolTimedOut(error),
            sqlx::Error::Database(database_error) => match database_error.kind() {
                ErrorKind::UniqueViolation => Self::UniqueViolation(error),
                ErrorKind::ForeignKeyViolation => Self::ForeignKeyViolation(error),
                _ => Self::QueryFailed(error),
            },
            _ => Self::QueryFailed(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    /// Verify that the classified timeout retains SQLx's original error.
    #[test]
    fn pool_timeout_preserves_its_source() {
        let error = DatabaseError::from(sqlx::Error::PoolTimedOut);

        assert_eq!(error.to_string(), "pool timed out");
        assert!(matches!(
            error.source().and_then(|source| source.downcast_ref()),
            Some(sqlx::Error::PoolTimedOut)
        ));
    }
}
