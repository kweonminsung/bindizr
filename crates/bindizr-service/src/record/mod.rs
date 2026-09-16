mod bulk;
mod create;
mod delete;
mod get;
mod import;
mod matching;
mod update;
mod validation;

use bindizr_core::dns::dnssec::rdata_presentation;
pub(crate) use matching::matches_record;
pub(crate) use validation::{
    AddOutcome, validate_delete_constraints, validate_record_name_in_zone, validate_record_ttl,
};

use crate::{
    model::{dnssec_record::DnssecRecordWithZone, record::RecordWithZone},
    types::{GetRecordResponse, RecordValueRequest},
};

/// Business logic for creating, updating, and querying DNS records.
#[derive(Clone)]
pub struct RecordService;

/// One row of the records listing: a user record or, behind the `signed`
/// flag, a row of the derived DNSSEC plane.
#[derive(Debug)]
enum ListedRecord {
    User(RecordWithZone),
    Derived(DnssecRecordWithZone),
}

impl ListedRecord {
    /// Render the row for the API: a user record keeps its id, a derived
    /// DNSSEC row carries none and renders its RDATA in presentation form.
    fn to_response(&self) -> GetRecordResponse {
        match self {
            ListedRecord::User(record) => GetRecordResponse::from_record_with_zone(record),
            ListedRecord::Derived(row) => GetRecordResponse {
                id: None,
                name: row.name.to_fqdn(&row.zone_name),
                record_type: row.record_type.to_string(),
                value: RecordValueRequest::String(rdata_presentation(row.record_type, &row.rdata)),
                ttl: row.ttl,
                priority: None,
                zone_id: row.zone_id,
                zone_name: row.zone_name.to_fqdn(),
            },
        }
    }
}

pub(crate) use validation::{parse_record_type, validate_record_add_constraints_normalized};
