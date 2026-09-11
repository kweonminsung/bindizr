//! The transaction handle the three backends share, and the lock levels a
//! transactional read names.

use sqlx::{MySql, Postgres, Sqlite};

use crate::{DatabasePool, error::DatabaseError, get_pool};

/// How strongly a transactional read locks the rows it returns. Every `_tx`
/// read names one, so the locking model reads off the call site; the two that
/// take none read rows the caller's zone lock already covers. Granularity
/// is the backend's: MySQL and PostgreSQL lock rows, SQLite's whole-database
/// write lock already covers every level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockLevel {
    /// The caller mutates these rows in this transaction.
    Exclusive,
    /// The caller only derives output from these rows, but they must not
    /// change before it commits.
    Shared,
    /// None needed: a lock the caller already holds — in practice the zone row,
    /// which every zone-data mutation takes first — covers these rows.
    None,
}

/// A database transaction spanning any of the supported backends.
pub struct RepositoryTx<'a>(RepositoryTxKind<'a>);

enum RepositoryTxKind<'a> {
    MySQL(sqlx::Transaction<'a, MySql>),
    PostgreSQL(sqlx::Transaction<'a, Postgres>),
    SQLite(sqlx::Transaction<'a, Sqlite>),
}

pub async fn begin_tx() -> Result<RepositoryTx<'static>, DatabaseError> {
    // IMMEDIATE takes SQLite's write lock up front so a read-then-write
    // transaction can't fail late with "database is locked".
    begin("BEGIN IMMEDIATE").await
}

/// Begin a transaction for multi-statement reads that write nothing: SQLite
/// readers then run concurrently instead of taking the single writer slot.
pub async fn begin_read_tx() -> Result<RepositoryTx<'static>, DatabaseError> {
    begin("BEGIN DEFERRED").await
}

/// Shared opener; only SQLite's BEGIN statement distinguishes the two.
async fn begin(sqlite_begin: &'static str) -> Result<RepositoryTx<'static>, DatabaseError> {
    match get_pool() {
        DatabasePool::MySQL(pool) => pool
            .begin()
            .await
            .map(|tx| RepositoryTx(RepositoryTxKind::MySQL(tx)))
            .map_err(|e| DatabaseError::TransactionFailed(e.to_string())),
        DatabasePool::PostgreSQL(pool) => pool
            .begin()
            .await
            .map(|tx| RepositoryTx(RepositoryTxKind::PostgreSQL(tx)))
            .map_err(|e| DatabaseError::TransactionFailed(e.to_string())),
        DatabasePool::SQLite(pool) => pool
            .begin_with(sqlite_begin)
            .await
            .map(|tx| RepositoryTx(RepositoryTxKind::SQLite(tx)))
            .map_err(|e| DatabaseError::TransactionFailed(e.to_string())),
    }
}

impl<'a> RepositoryTx<'a> {
    pub async fn commit(self) -> Result<(), DatabaseError> {
        match self.0 {
            RepositoryTxKind::MySQL(tx) => tx
                .commit()
                .await
                .map_err(|e| DatabaseError::TransactionFailed(e.to_string())),
            RepositoryTxKind::PostgreSQL(tx) => tx
                .commit()
                .await
                .map_err(|e| DatabaseError::TransactionFailed(e.to_string())),
            RepositoryTxKind::SQLite(tx) => tx
                .commit()
                .await
                .map_err(|e| DatabaseError::TransactionFailed(e.to_string())),
        }
    }

    pub async fn rollback(self) -> Result<(), DatabaseError> {
        match self.0 {
            RepositoryTxKind::MySQL(tx) => tx
                .rollback()
                .await
                .map_err(|e| DatabaseError::TransactionFailed(e.to_string())),
            RepositoryTxKind::PostgreSQL(tx) => tx
                .rollback()
                .await
                .map_err(|e| DatabaseError::TransactionFailed(e.to_string())),
            RepositoryTxKind::SQLite(tx) => tx
                .rollback()
                .await
                .map_err(|e| DatabaseError::TransactionFailed(e.to_string())),
        }
    }

    /// Borrow the underlying MySQL transaction, erroring if this handle wraps a
    /// different backend.
    pub(crate) fn as_mysql(&mut self) -> Result<&mut sqlx::Transaction<'a, MySql>, DatabaseError> {
        match &mut self.0 {
            RepositoryTxKind::MySQL(tx) => Ok(tx),
            _ => Err(DatabaseError::TransactionFailed(
                "transaction kind mismatch (expected MySQL)".to_string(),
            )),
        }
    }

    /// Borrow the underlying PostgreSQL transaction, erroring if this handle
    /// wraps a different backend.
    pub(crate) fn as_postgres(
        &mut self,
    ) -> Result<&mut sqlx::Transaction<'a, Postgres>, DatabaseError> {
        match &mut self.0 {
            RepositoryTxKind::PostgreSQL(tx) => Ok(tx),
            _ => Err(DatabaseError::TransactionFailed(
                "transaction kind mismatch (expected PostgreSQL)".to_string(),
            )),
        }
    }

    /// Borrow the underlying SQLite transaction, erroring if this handle wraps a
    /// different backend.
    pub(crate) fn as_sqlite(
        &mut self,
    ) -> Result<&mut sqlx::Transaction<'a, Sqlite>, DatabaseError> {
        match &mut self.0 {
            RepositoryTxKind::SQLite(tx) => Ok(tx),
            _ => Err(DatabaseError::TransactionFailed(
                "transaction kind mismatch (expected SQLite)".to_string(),
            )),
        }
    }
}
