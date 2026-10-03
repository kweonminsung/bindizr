//! Application services for bindizr: zone, record, token, and NOTIFY
//! workflows over `bindizr_db`, with explicit context and transaction dependencies.

pub mod authorization;
pub mod context;
pub mod dns_client;
pub mod dnssec;
pub mod dnssec_policy;
pub mod dynamic_update;
pub mod error;
pub mod external_dns;
pub(crate) mod grant_pattern;
pub mod notify;
mod pagination;
pub mod permission;
pub mod record;
pub mod role;
pub mod secondary;
pub(crate) mod serial;
pub(crate) mod text;
pub(crate) mod time;
pub mod token;
mod transaction;
pub mod transfer;
pub mod tsig_key;
pub(crate) mod ttl;
pub mod types;
pub mod zone;

pub(crate) use bindizr_core::model;
pub(crate) use bindizr_db::Transaction;
pub use context::Context;
