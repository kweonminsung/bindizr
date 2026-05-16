pub mod auth;
pub mod error;
pub mod record;
mod repository;
pub mod token;
pub mod utils;
pub mod zone;

pub(crate) use repository::RepositoryTx;

use error::ServiceError;
use repository::RepositoryService;

pub(crate) async fn begin_tx(
    internal_msg: &'static str,
) -> Result<RepositoryTx<'static>, ServiceError> {
    RepositoryService::begin_tx(internal_msg).await
}
