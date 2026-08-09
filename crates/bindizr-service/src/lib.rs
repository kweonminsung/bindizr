//! Application services for bindizr: zone, record, token, and NOTIFY
//! workflows built on the repository layer.

pub mod authorization;
pub mod dynamic_update;
pub mod error;
pub mod external_dns;
pub mod notify;
mod pagination;
pub(crate) mod policy_pattern;
pub mod record;
mod repository;
pub mod serial;
pub(crate) mod timing;
pub mod token;
pub mod tsig_key;
pub mod types;
pub mod zone;

pub(crate) use bindizr_core::{
    log_debug, log_debug_enabled, log_error, log_info, log_warn, metrics, model,
};
pub(crate) use bindizr_db as database;
pub(crate) use repository::RepositoryTx;
