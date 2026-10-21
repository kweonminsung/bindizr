//! Registered secondaries: management, diagnostics, and outbound NOTIFY credentials.

mod check;
mod create;
mod delete;
mod get;
mod notify;
mod transfers;
mod update;
mod validation;

pub use check::{check, check_enabled};
pub use create::create;
pub use delete::delete;
pub use get::{get, list, list_enabled};
pub(crate) use get::{load_response, lookup_by_name};
pub(crate) use notify::{find_notify_signing_key, find_notify_tsig_key};
pub use transfers::list_transfers;
pub(crate) use transfers::summarize_transfers;
pub use update::update;
pub(crate) use validation::{normalize_secondary_address, normalize_secondary_name};
