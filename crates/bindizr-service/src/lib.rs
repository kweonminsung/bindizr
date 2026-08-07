//! Application services for bindizr: zone, record, token, and NOTIFY
//! workflows built on the repository layer.

pub mod auth;
pub mod authorization;
pub mod error;
pub mod external_dns;
pub mod notify;
mod pagination;
pub mod record;
mod repository;
pub mod serial;
pub(crate) mod timing;
pub mod token;
pub mod tsig_key;
pub mod types;
pub(crate) mod validation;
pub mod zone;

pub(crate) use bindizr_core::{
    log_debug, log_debug_enabled, log_error, log_info, log_warn, metrics, model,
};
pub(crate) use bindizr_db as database;
use error::ServiceError;
use repository::RepositoryService;
pub use repository::RepositoryTx;

/// Begin a repository transaction; `internal_msg` is the error message on failure.
pub async fn begin_tx(internal_msg: &'static str) -> Result<RepositoryTx<'static>, ServiceError> {
    RepositoryService::begin_tx(internal_msg).await
}
