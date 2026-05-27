mod api;
mod cli;
pub mod error;
mod socket;

pub use api::router::ApiRouter;
pub use bindizr_core::config;
pub(crate) use bindizr_core::logger;
pub use bindizr_core::{log_debug, log_error, log_info, log_trace, log_warn};
pub use bindizr_db::database;
pub(crate) use bindizr_db::service;
pub use bindizr_dns as dns;
pub use cli::execute;
