//! Application services for bindizr: zone, record, token, and NOTIFY
//! workflows built on the repository layer.

pub mod authorization;
pub mod dns_client;
pub mod dnssec;
pub mod dnssec_policy;
pub mod dynamic_update;
pub mod error;
pub mod external_dns;
pub(crate) mod grant_pattern;
pub(crate) mod identifier;
pub mod notify;
pub mod record;
mod repository;
pub mod secondary;
pub(crate) mod serial;
pub(crate) mod timing;
pub mod token;
pub mod tsig_key;
pub(crate) mod ttl;
pub mod types;
pub mod zone;

pub(crate) use bindizr_core::{metrics, model};
pub(crate) use bindizr_db as database;
pub(crate) use repository::RepositoryTx;
