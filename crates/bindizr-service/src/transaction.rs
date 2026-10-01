//! The transaction plumbing every mutation flow shares: open one on the
//! context's database, then commit on success or roll back on failure.

use bindizr_db::Transaction;

use crate::{Context, error::ServiceError};

/// Begin a database transaction and translate any startup error.
pub(crate) async fn begin_tx(
    cx: &Context,
    internal_msg: &'static str,
) -> Result<Transaction<'static>, ServiceError> {
    cx.db().begin().await.map_err(|e| {
        log::error!("Failed to begin transaction: {}", e);
        ServiceError::internal_with_source(internal_msg, e)
    })
}

/// Begin a transaction for a caller that only reads; see [`bindizr_db::Db::begin_read`].
pub(crate) async fn begin_read_tx(
    cx: &Context,
    internal_msg: &'static str,
) -> Result<Transaction<'static>, ServiceError> {
    cx.db().begin_read().await.map_err(|e| {
        log::error!("Failed to begin transaction: {}", e);
        ServiceError::internal_with_source(internal_msg, e)
    })
}

/// Commit on success, roll back on failure. `E` is the caller's error
/// type, so a front end with its own error taxonomy keeps this one
/// transaction helper.
pub(crate) async fn finish_tx<T, E: From<ServiceError>>(
    tx: Transaction<'static>,
    apply_result: Result<T, E>,
    internal_msg: &'static str,
) -> Result<T, E> {
    match apply_result {
        Ok(value) => {
            tx.commit().await.map_err(|e| {
                log::error!("Failed to commit transaction: {}", e);
                E::from(ServiceError::internal_with_source(internal_msg, e))
            })?;
            Ok(value)
        }
        Err(err) => {
            if let Err(e) = tx.rollback().await {
                log::error!("Failed to rollback transaction: {}", e);
            }
            Err(err)
        }
    }
}

/// Roll back however the work ended: a preview writes only to plan against.
pub(crate) async fn discard_tx<T, E: From<ServiceError>>(
    tx: Transaction<'static>,
    apply_result: Result<T, E>,
) -> Result<T, E> {
    if let Err(e) = tx.rollback().await {
        log::error!("Failed to rollback transaction: {}", e);
    }
    apply_result
}
