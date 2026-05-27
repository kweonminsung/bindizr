pub mod auth;
pub mod error;
pub mod notify;
pub mod record;
mod repository;
pub mod token;
pub mod utils;
pub mod zone;

pub use repository::RepositoryTx;

use error::ServiceError;
use repository::RepositoryService;

pub async fn begin_tx(internal_msg: &'static str) -> Result<RepositoryTx<'static>, ServiceError> {
    RepositoryService::begin_tx(internal_msg).await
}
