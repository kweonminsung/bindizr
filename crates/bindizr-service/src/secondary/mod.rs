//! Registered secondaries: management, diagnostics, and outbound NOTIFY credentials.

mod check;
mod create;
mod delete;
mod get;
mod notify;
mod target;
mod transfers;
mod update;
mod validation;

pub use check::{check, check_enabled};
pub use create::create;
pub use delete::delete;
pub use get::{get, list, list_enabled};
pub(crate) use get::{lookup_by_name, lookup_response};
pub(crate) use notify::{find_notify_signing_key, find_notify_tsig_key};
pub(crate) use target::{SecondaryTarget, resolve_enabled};
pub(crate) use transfers::{resolve_ips, summarize_transfers_by_clients};
pub use update::update;
pub(crate) use validation::{normalize_address, normalize_name};
