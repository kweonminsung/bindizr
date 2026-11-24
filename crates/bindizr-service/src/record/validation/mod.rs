//! Record request validation: parsing the request's record fields, owner
//! normalization, owner-local constraints (CNAME, DNAME, NS, MX, WKS, DS, one
//! TTL per name and type), the duplicate and add-outcome check, and the
//! stored-name wire fit check.

mod index;

use bindizr_core::dns::Ttl;
use bindizr_core::dns::name::{OwnerName, ParseNameError, ZoneName};
use bindizr_core::dns::record::CaaRecordValue;
use bindizr_core::model::record::{Record, RecordId, RecordType};
use bindizr_core::model::zone::Zone;
pub(crate) use index::RecordConstraintIndex;

use crate::error::ServiceError;
use crate::types::RecordValue;
use crate::{Transaction, ttl};

/// Parsed record fields; an omitted TTL is resolved under the zone lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedRecord {
    pub(crate) record_type: RecordType,
    pub(crate) value: String,
    pub(crate) ttl: Option<Ttl>,
    pub(crate) priority: Option<i32>,
}

/// Parse the record fields, keeping the type available to authorize the
/// target before reporting errors in its value or TTL.
pub(crate) fn parse_record_fields(
    record_type: &str,
    value: &RecordValue,
    ttl: Option<i64>,
    priority: Option<i32>,
) -> (Option<RecordType>, Result<ParsedRecord, ServiceError>) {
    let record_type = match parse_record_type(record_type) {
        Ok(record_type) => record_type,
        Err(error) => return (None, Err(error)),
    };

    (
        Some(record_type),
        encode_record_fields(record_type, value, ttl, priority),
    )
}

/// Validate a known record type's TTL, priority, and stored value.
fn encode_record_fields(
    record_type: RecordType,
    value: &RecordValue,
    ttl: Option<i64>,
    priority: Option<i32>,
) -> Result<ParsedRecord, ServiceError> {
    let ttl = ttl.map(ttl::validate_record_ttl).transpose()?;
    let priority = record_type.stored_priority(priority);
    let value = value
        .to_encoded_value(record_type, priority)
        .map_err(ServiceError::invalid_record_value)?;

    validate_management_value(record_type, &value)?;

    Ok(ParsedRecord {
        record_type,
        value,
        ttl,
        priority,
    })
}

/// Validate newly authored values while leaving imported opaque flags intact.
pub(crate) fn validate_management_value(
    record_type: RecordType,
    value: &str,
) -> Result<(), ServiceError> {
    if record_type == RecordType::Caa {
        CaaRecordValue::parse(value)
            .and_then(|caa| caa.validate_creation())
            .map_err(ServiceError::invalid_record_value)?;
    }
    Ok(())
}

/// Parse a supported record type from request text.
pub(crate) fn parse_record_type(value: &str) -> Result<RecordType, ServiceError> {
    value
        .parse::<RecordType>()
        .map_err(ServiceError::invalid_input)
}

/// Validate and normalize a record owner relative to its zone.
pub(crate) fn normalize_record_owner_name(
    input_name: &str,
    zone_name: &ZoneName,
) -> Result<OwnerName, ServiceError> {
    OwnerName::parse_in_zone(input_name, zone_name).map_err(|error| match error {
        ParseNameError::OutsideZone => ServiceError::invalid_record_name(format!(
            "record name '{input_name}' is outside zone '{zone_name}'"
        )),
        other => ServiceError::invalid_record_name(format!("record name {other}")),
    })
}

/// Return whether any record already holds the candidate's rdata. Canonical
/// comparison keeps protocol and API callers agreeing on "already exists".
fn has_matching_rdata<'a>(
    records: impl IntoIterator<Item = &'a Record>,
    record_type: RecordType,
    value: &str,
    priority: Option<i32>,
) -> bool {
    // One comparison form for the candidate, however many rows it meets.
    let wanted = record_type.to_comparison_key(value, priority);
    records.into_iter().any(|record| {
        record.record_type == record_type
            && record_type.to_comparison_key(&record.value, record.priority) == wanted
    })
}

/// Validate a normalized record, excluding the row being replaced.
pub(crate) fn validate_record_constraints(
    records: &[Record],
    owner: &OwnerName,
    record_type: RecordType,
    value: &str,
    ttl: Ttl,
    priority: Option<i32>,
    except_record_id: Option<RecordId>,
) -> Result<(), ServiceError> {
    RecordConstraintIndex::new(
        records
            .iter()
            .filter(|record| record.name == *owner && except_record_id != Some(record.id)),
    )
    .validate(owner, record_type, value, ttl, priority)
}

/// Refuse a stored name that no longer fits the wire under `zone_name`, the
/// zone a rename or a rollback pairs it with.
pub(crate) fn validate_record_name_in_zone(
    owner: &OwnerName,
    zone_name: &ZoneName,
) -> Result<(), ServiceError> {
    owner.to_wire(zone_name).map(|_| ()).map_err(|error| {
        ServiceError::invalid_record_name(format!(
            "record name '{owner}' under zone '{zone_name}' {error}"
        ))
    })
}

/// What an add resolves to against the records already in the zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddResult {
    /// Nothing holds this rdata and every constraint passed.
    New,
    Duplicate,
}

/// Validate an add against records loaded in the caller's transaction.
/// Identical RDATA yields [`AddResult::Duplicate`] per RFC 2136, Section 3.4.2.2;
/// API callers use the validator directly and report the duplicate as a conflict.
pub(crate) async fn validate_add_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
    owner: &OwnerName,
    record_type: RecordType,
    value: &str,
    ttl: Ttl,
    priority: Option<i32>,
) -> Result<AddResult, ServiceError> {
    // Only records sharing the owner name can conflict, so load just those
    // instead of the whole zone.
    let records_at_name = bindizr_db::record::list_by_name_tx(tx, zone.id, owner)
        .await
        .map_err(|error| ServiceError::internal_with_source("failed to load records", error))?;

    if has_matching_rdata(records_at_name.iter(), record_type, value, priority) {
        return Ok(AddResult::Duplicate);
    }

    validate_record_constraints(
        &records_at_name,
        owner,
        record_type,
        value,
        ttl,
        priority,
        None,
    )?;

    Ok(AddResult::New)
}

#[cfg(test)]
mod tests;
