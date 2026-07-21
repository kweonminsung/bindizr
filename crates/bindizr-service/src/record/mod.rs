mod bulk;
mod create;
mod delete;
mod get;
mod import;
mod record_value;
mod update;
mod validation;
mod zonefile;

pub use validation::{validate_add_constraints_tx, validate_delete_constraints};

/// Business logic for creating, updating, and querying DNS records.
#[derive(Clone)]
pub struct RecordService;

pub(crate) use bulk::{delete_records_tx, insert_validated_records_tx, load_zone_tx};
pub(crate) use record_value::record_values_equal;
pub(crate) use validation::validate_record_add_constraints_normalized;
