//! The transaction handle the three backends share, and the lock levels a
//! transactional read names.

use sqlx::{MySql, Postgres, Sqlite};

use crate::error::DatabaseError;

/// Row locks requested on MySQL/PostgreSQL. SQLite relies on its transaction
/// mode: a database write lock for mutations, a snapshot for read-only work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockLevel {
    /// The caller mutates these rows in this transaction.
    Exclusive,
    /// The caller only derives output from these rows, but they must not
    /// change before it commits.
    Shared,
    /// No row lock: either an existing lock protects these rows, or the caller
    /// accepts changes between reads.
    Unlocked,
}

impl LockLevel {
    /// The locking clause for this level, as a suffix appended after any
    /// `ORDER BY`. SQLite locks the whole database instead, so it never calls
    /// this.
    pub(crate) fn clause(self) -> &'static str {
        match self {
            LockLevel::Exclusive => " FOR UPDATE",
            LockLevel::Shared => " FOR SHARE",
            LockLevel::Unlocked => "",
        }
    }
}

/// A database transaction on whichever backend the `Db` connected to. A root
/// `_tx` function matches it to hand the backend its own `sqlx::Transaction`.
#[derive(Debug)]
pub struct Transaction<'a>(pub(crate) TransactionKind<'a>);

#[derive(Debug)]
pub(crate) enum TransactionKind<'a> {
    MySql(sqlx::Transaction<'a, MySql>),
    Postgres(sqlx::Transaction<'a, Postgres>),
    Sqlite(sqlx::Transaction<'a, Sqlite>),
}

impl Transaction<'_> {
    /// Commit the transaction on its database backend.
    pub async fn commit(self) -> Result<(), DatabaseError> {
        match self.0 {
            TransactionKind::MySql(tx) => tx.commit().await,
            TransactionKind::Postgres(tx) => tx.commit().await,
            TransactionKind::Sqlite(tx) => tx.commit().await,
        }
        .map_err(DatabaseError::TransactionFailed)
    }

    /// Roll back the transaction on its database backend.
    pub async fn rollback(self) -> Result<(), DatabaseError> {
        match self.0 {
            TransactionKind::MySql(tx) => tx.rollback().await,
            TransactionKind::Postgres(tx) => tx.rollback().await,
            TransactionKind::Sqlite(tx) => tx.rollback().await,
        }
        .map_err(DatabaseError::TransactionFailed)
    }
}
