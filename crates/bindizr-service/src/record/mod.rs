//! Business logic for creating, updating, and querying DNS records.

mod bulk;
mod changes;
mod create;
mod delete;
mod get;
mod update;
mod validation;

use bindizr_core::dns::name::{OwnerName, ZoneName};
use bindizr_core::model::activity_log::ActivityTarget;
use bindizr_core::model::dnssec_record::DnssecRecordWithZone;
use bindizr_core::model::record::{Record, RecordType, RecordWithZone};
use bindizr_core::model::zone::ZoneId;
pub use bulk::create_bulk;
pub(crate) use changes::{create_with_changes_tx, delete_with_changes_tx, update_with_changes_tx};
pub use create::create;
pub use delete::{delete, delete_matching};
pub use get::{count_all, get, list_by_filter_with_zone};
pub use update::{update, update_by_name};
pub(crate) use validation::{
    AddResult, ParsedRecord, RecordConstraintIndex, normalize_record_owner_name,
    parse_record_fields, parse_record_type, validate_add_tx, validate_management_value,
    validate_record_constraints, validate_record_name_in_zone,
};

use crate::authorization::{Caller, GrantedRecord, ReadableRecords};
use crate::types::{RecordResponse, RecordValue};

/// Identify the record with the same relative owner and type used by grants.
pub(crate) fn activity_target(zone_name: &ZoneName, record: &Record) -> ActivityTarget {
    ActivityTarget {
        record_id: record.id.written().map(i32::from),
        record_name: Some(record.name.to_string()),
        record_type: Some(record.record_type.to_string()),
        ..crate::zone::activity_target(zone_name)
    }
}

/// An API-visible user or derived DNSSEC record; SOA stays in zone metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ServedRecord {
    User(RecordWithZone),
    Derived(DnssecRecordWithZone),
}

impl ServedRecord {
    /// Return the zone that owns this user or derived row.
    fn zone_id(&self) -> ZoneId {
        match self {
            Self::User(record) => record.record.zone_id,
            Self::Derived(record) => record.zone_id,
        }
    }
}

impl GrantedRecord for ServedRecord {
    /// Return the owner name in the row's zone.
    fn name(&self) -> &OwnerName {
        match self {
            Self::User(record) => &record.record.name,
            Self::Derived(record) => &record.name,
        }
    }

    /// Return the user type, or no type for a derived row's grant matching.
    fn record_type(&self) -> Option<RecordType> {
        match self {
            Self::User(record) => Some(record.record.record_type),
            Self::Derived(_) => None,
        }
    }
}

/// Render checked rows; derived DNSSEC records have no id or actions.
fn build_record_responses(
    caller: &Caller,
    records: &ReadableRecords<ServedRecord>,
) -> Vec<RecordResponse> {
    records
        .as_slice()
        .iter()
        .map(|record| match record {
            ServedRecord::User(record) => RecordResponse::from_record(
                &record.record,
                &record.zone_name,
                caller.record_actions(
                    record.record.zone_id,
                    &record.record.name,
                    record.record.record_type,
                ),
            ),
            ServedRecord::Derived(record) => RecordResponse {
                id: None,
                name: record.name.to_fqdn(&record.zone_name),
                record_type: record.record_type.into(),
                value: RecordValue::Text(record.rdata.to_presentation(record.record_type)),
                ttl: record.ttl,
                priority: None,
                zone_id: record.zone_id,
                zone_name: record.zone_name.to_string(),
                actions: Vec::new(),
            },
        })
        .collect()
}

#[cfg(test)]
mod tests;
