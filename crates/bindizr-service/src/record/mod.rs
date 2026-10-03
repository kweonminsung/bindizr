//! Business logic for creating, updating, and querying DNS records.

mod bulk;
mod create;
mod delete;
mod get;
mod import;
mod update;
mod validation;

pub use bulk::create_bulk;
pub(crate) use bulk::{
    PreparedRecord, create_with_changes_tx, delete_with_changes_tx, parse_record_request,
    update_with_changes_tx,
};
pub use create::create;
pub use delete::{delete, delete_matching};
pub use get::{count_all, get, list_with_zone_by_filter};
pub use import::import_zone;
pub use update::{update, update_by_name};
pub(crate) use validation::{
    AddResult, normalize_record_owner_name, validate_add_tx, validate_record_name_in_zone,
};

use crate::{
    authorization::Caller,
    model::{dnssec_record::DnssecRecordWithZone, record::RecordWithZone},
    types::{GetRecordResponse, RecordValueRequest},
};

/// One row of the records listing: a user record or, behind the `signed`
/// flag, a row of the derived DNSSEC plane.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ListedRecord {
    User(RecordWithZone),
    Derived(DnssecRecordWithZone),
}

/// Render a listed row for the API: a user record keeps its id and the
/// caller's actions on it, a derived DNSSEC row carries neither and renders
/// its RDATA in presentation form.
fn build_record_response(caller: &Caller, record: &ListedRecord) -> GetRecordResponse {
    match record {
        ListedRecord::User(record) => GetRecordResponse::from_record(
            &record.record(),
            &record.zone_name,
            caller.record_actions(record.zone_id, &record.name, &record.record_type),
        ),
        ListedRecord::Derived(row) => GetRecordResponse {
            id: None,
            name: row.name.to_fqdn(&row.zone_name),
            record_type: row.record_type.into(),
            value: RecordValueRequest::Text(row.rdata.to_presentation(row.record_type)),
            ttl: row.ttl,
            priority: None,
            zone_id: row.zone_id,
            zone_name: row.zone_name.to_fqdn(),
            actions: Vec::new(),
        },
    }
}

pub(crate) use validation::validate_record_add_constraints_normalized;
