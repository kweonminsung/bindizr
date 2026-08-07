mod bulk;
mod create;
mod delete;
mod get;
mod import;
mod update;
mod validation;
mod zonefile;

pub use validation::validate_delete_constraints;

/// Business logic for creating, updating, and querying DNS records.
#[derive(Clone)]
pub struct RecordService;

pub(crate) use validation::{parse_record_type, validate_record_add_constraints_normalized};
