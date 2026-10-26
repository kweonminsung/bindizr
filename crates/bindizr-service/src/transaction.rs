//! The transaction plumbing every mutation flow shares: open one on the
//! context's database, then commit on success or roll back on failure.

use bindizr_db::Transaction;

use crate::Context;
use crate::error::ServiceError;

/// Begin a database transaction and translate any startup error.
pub(crate) async fn begin_tx(
    cx: &Context,
    message: &'static str,
) -> Result<Transaction<'static>, ServiceError> {
    cx.db().begin().await.map_err(|error| {
        log::error!("Failed to begin transaction: {}", error);
        ServiceError::internal_with_source(message, error)
    })
}

/// Begin a transaction for a caller that only reads; see [`bindizr_db::Db::begin_read`].
pub(crate) async fn begin_read_tx(
    cx: &Context,
    message: &'static str,
) -> Result<Transaction<'static>, ServiceError> {
    cx.db().begin_read().await.map_err(|error| {
        log::error!("Failed to begin transaction: {}", error);
        ServiceError::internal_with_source(message, error)
    })
}

/// Commit on success or roll back on failure, preserving the caller's error type.
pub(crate) async fn finish_tx<T, E: From<ServiceError>>(
    tx: Transaction<'static>,
    apply_result: Result<T, E>,
    message: &'static str,
) -> Result<T, E> {
    match apply_result {
        Ok(value) => {
            tx.commit().await.map_err(|error| {
                log::error!("Failed to commit transaction: {}", error);
                E::from(ServiceError::internal_with_source(message, error))
            })?;
            Ok(value)
        }
        Err(error) => {
            // A rollback failure must not replace the original operation error.
            if let Err(error) = tx.rollback().await {
                log::error!("Failed to rollback transaction: {}", error);
            }
            Err(error)
        }
    }
}
