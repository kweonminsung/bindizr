pub mod auth;
pub mod error;
pub mod notify;
pub mod record;
mod repository;
pub mod serial;
pub mod token;
pub mod types;
pub mod zone;

pub use repository::RepositoryTx;

pub(crate) use bindizr_core::model;
pub(crate) use bindizr_core::{log_error, log_info, log_warn};
pub(crate) use bindizr_db as database;

use error::ServiceError;
use repository::RepositoryService;

pub async fn begin_tx(internal_msg: &'static str) -> Result<RepositoryTx<'static>, ServiceError> {
    RepositoryService::begin_tx(internal_msg).await
}
