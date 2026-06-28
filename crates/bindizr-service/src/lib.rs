pub mod auth;
pub mod error;
pub mod notify;
mod pagination;
pub mod record;
mod repository;
pub mod serial;
pub mod token;
pub mod types;
pub(crate) mod validation;
pub mod zone;

pub(crate) use bindizr_core::{log_error, log_info, log_warn, model};
pub(crate) use bindizr_db as database;
use error::ServiceError;
use repository::RepositoryService;
pub use repository::RepositoryTx;

pub async fn begin_tx(internal_msg: &'static str) -> Result<RepositoryTx<'static>, ServiceError> {
    RepositoryService::begin_tx(internal_msg).await
}
