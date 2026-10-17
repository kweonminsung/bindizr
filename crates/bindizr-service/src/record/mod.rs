//! Business logic for creating, updating, and querying DNS records.

mod bulk;
mod create;
mod delete;
mod get;
mod import;
mod update;
mod validation;

pub use bulk::create_bulk;
pub(crate) use bulk::{create_with_changes_tx, delete_with_changes_tx, update_with_changes_tx};
pub use create::create;
pub use delete::{delete, delete_matching};
pub use get::{count_all, get, list_by_filter_with_zone};
pub use import::{import_zone, import_zones};
pub use update::{update, update_by_name};
pub(crate) use validation::{
    AddResult, validate_add_tx, validate_record_constraints, validate_record_name_in_zone,
};

use crate::{
    authorization::Caller,
    model::{dnssec_record::DnssecRecordWithZone, record::RecordWithZone},
    types::{RecordResponse, RecordValue},
};

/// An API-visible user or derived DNSSEC record; SOA stays in zone metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ServedRecord {
    User(RecordWithZone),
    Derived(DnssecRecordWithZone),
}

/// Render a served record; derived DNSSEC rows have presentation RDATA but no id or actions.
fn build_record_response(caller: &Caller, record: &ServedRecord) -> RecordResponse {
    match record {
        ServedRecord::User(record) => RecordResponse::from_record(
            &record.record(),
            &record.zone_name,
            caller.record_actions(record.zone_id, &record.name, &record.record_type),
        ),
        ServedRecord::Derived(row) => RecordResponse {
            id: None,
            name: row.name.to_fqdn(&row.zone_name),
            record_type: row.record_type.into(),
            value: RecordValue::Text(row.rdata.to_presentation(row.record_type)),
            ttl: row.ttl,
            priority: None,
            zone_id: row.zone_id,
            zone_name: row.zone_name.to_string(),
            actions: Vec::new(),
        },
    }
}
