mod create;
mod delete;
mod read;
mod update;
mod validation;

pub use validation::{
    find_identical_record_in_zone_tx, validate_record_add_constraints_tx,
    validate_record_delete_constraints,
};

#[derive(Clone)]
pub struct RecordService;
