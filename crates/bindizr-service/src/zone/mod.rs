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

pub(crate) use catalog_zone::refresh_catalog_from_zones;
pub use catalog_zone::{refresh_catalog, validate_catalog_zone_name};
pub use create::create;
pub(crate) use create::create_tx;
pub use delete::delete;
pub use export::export;
pub(crate) use force::force_increment_serial;
pub use get::{count, count_all, get_by_name, list, list_by_filter, ping};
pub(crate) use get::{find_by_name_tx, find_served_by_name_tx, lookup_by_name, lookup_by_name_tx};
pub use history::{diff_versions, get_version, list_versions, rollback};
pub use notify::notify;
pub use status::get_status;
pub use transfer::{
    IxfrPlan, TransferAccess, TransferContent, authorize_ixfr_plan_by_name,
    authorize_soa_content_by_name, authorize_transfer_by_name, authorize_transfer_content_by_name,
    refresh_catalog_content,
};
pub(crate) use update::soa_replacement_changes;
pub use update::update;
pub use validation::normalize_name;
pub(crate) use validation::{validate_name, validate_record_changes_tx};
pub(crate) use version::{advance_serial_tx, save_version_tx};
