//! Business logic for creating, updating, and querying DNS zones.

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

pub use catalog_zone::{advance_catalog_serial, validate_catalog_zone_name};
pub use create::create;
pub(crate) use create::create_tx;
pub use delete::delete;
pub use export::export;
pub(crate) use force::force_increment_serial;
pub use get::{count, count_all, get_by_name, list, list_by_filter, ping};
pub(crate) use get::{
    find_by_name_tx, find_served_by_name_tx, get_by_name_tx, lookup_by_name, lookup_by_name_tx,
};
pub use history::{diff_versions, get_version, list_versions, rollback};
pub use notify::notify;
pub use status::get_status;
pub use transfer::{
    TransferAccess, TransferContent, TransferDelta, authorize_catalog_content,
    authorize_transfer_by_name, authorize_transfer_content_by_name,
    authorize_transfer_delta_by_name,
};
pub use update::update;
pub use validation::normalize_name;
pub(crate) use version::{advance_serial_tx, save_version_tx};
