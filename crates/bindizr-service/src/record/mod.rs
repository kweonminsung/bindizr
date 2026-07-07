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
