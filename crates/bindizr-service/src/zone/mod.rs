mod catalog_zone;
mod create;
mod delete;
pub(crate) mod diff;
mod export;
mod force;
mod get;
pub(crate) mod history;
mod notify;
mod status;
mod transfer;
mod update;
pub(crate) mod validation;
pub(crate) mod version;

pub use transfer::{TransferAccess, TransferContent};

/// Business logic for creating, updating, and querying DNS zones.
#[derive(Clone)]
pub struct ZoneService;
