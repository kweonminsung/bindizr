//! DNS record constraint validation: CNAME/NS/MX/SOA rules, duplicate
//! detection, and owner-name normalization.

use bindizr_core::{
    dns::{
        Ttl,
        name::{OwnerName, ParseNameError, ZoneName},
        record::{CaaRecordValue, MxRecordValue},
    },
    model::record::RecordId,
};
use bindizr_db::LockLevel;

use crate::{
    Transaction,
    error::ServiceError,
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    ttl::validate_record_ttl,
    types::RecordValue,
};

/// Parsed record fields; an omitted TTL is resolved under the zone lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedRecord {
    pub(crate) record_type: RecordType,
    pub(crate) value: String,
    pub(crate) ttl: Option<Ttl>,
    pub(crate) priority: Option<i32>,
}

/// Parse the record type and encode the value into its record-row form.
pub(crate) fn parse_record_fields(
    record_type: &str,
    value: &RecordValue,
    ttl: Option<i32>,
    priority: Option<i32>,
) -> Result<ParsedRecord, ServiceError> {
    let record_type = parse_record_type(record_type)?;
    let ttl = ttl.map(validate_record_ttl).transpose()?;
    let priority = record_type.stored_priority(priority);
    let value = value
        .to_encoded_value(&record_type, priority)
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
pub(super) fn validate_management_value(
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
        .map_err(|_| ServiceError::invalid_input(format!("invalid record type: {}", value)))
}

/// Validate and normalize a record owner relative to its zone.
pub(crate) fn normalize_record_owner_name(
    input_name: &str,
    zone_name: &ZoneName,
) -> Result<OwnerName, ServiceError> {
    let owner = OwnerName::parse_in_zone(input_name, zone_name).map_err(|e| match e {
        ParseNameError::OutsideZone => ServiceError::invalid_record_name(format!(
            "record name '{}' is outside zone '{}'",
            input_name, zone_name
        )),
        other => ServiceError::invalid_record_name(format!("record name {}", other)),
    })?;

    Ok(owner)
}

/// Whether any record already holds the candidate's rdata. Canonical
/// comparison keeps protocol and API callers agreeing on "already exists".
fn has_matching_rdata<'a>(
    records: impl IntoIterator<Item = &'a Record>,
    record_type: &RecordType,
    value: &str,
    priority: Option<i32>,
) -> bool {
    records
        .into_iter()
        .any(|r| r.record_type == *record_type && r.has_rdata(value, priority))
}

/// Validate a normalized record, excluding the row being replaced.
pub(crate) fn validate_record_constraints(
    records: &[Record],
    stored_name: &OwnerName,
    record_type: &RecordType,
    value: &str,
    ttl: Ttl,
    priority: Option<i32>,
    except_record_id: Option<RecordId>,
) -> Result<(), ServiceError> {
    record_type
        .validate_value(value, priority)
        .map_err(ServiceError::invalid_record_value)?;

    if *record_type == RecordType::Cname && stored_name.is_apex() {
        return Err(ServiceError::invalid_record_name(
            "CNAME record cannot have '@' as name".to_string(),
        ));
    }

    let records_at_name: Vec<_> = records
        .iter()
        .filter(|r| r.name == *stored_name && except_record_id.map(|id| id != r.id).unwrap_or(true))
        .collect();

    if has_matching_rdata(
        records_at_name.iter().copied(),
        record_type,
        value,
        priority,
    ) {
        return Err(ServiceError::record_conflict(format!(
            "record '{}' {} '{}' already exists in this zone",
            stored_name, record_type, value
        )));
    }

    if *record_type == RecordType::Mx {
        let adding_null_mx = MxRecordValue::parse(value, priority).is_ok_and(|mx| mx.is_null());
        let has_existing_null_mx = records_at_name.iter().any(|r| {
            r.record_type == RecordType::Mx
                && MxRecordValue::parse(&r.value, r.priority).is_ok_and(|mx| mx.is_null())
        });
        let has_existing_mx = records_at_name
            .iter()
            .any(|r| r.record_type == RecordType::Mx);

        if (adding_null_mx && has_existing_mx) || (!adding_null_mx && has_existing_null_mx) {
            return Err(ServiceError::record_conflict(format!(
                "null MX record for '{}' cannot coexist with other MX records",
                stored_name
            )));
        }
    }

    if !records_at_name.is_empty() {
        if *record_type == RecordType::Cname {
            return Err(ServiceError::record_conflict(format!(
                "another record with name '{}' already exists in this zone, so CNAME cannot be used",
                stored_name
            )));
        }
        if records_at_name
            .iter()
            .any(|r| r.record_type == RecordType::Cname)
        {
            return Err(ServiceError::record_conflict(format!(
                "A CNAME record with name '{}' already exists in this zone",
                stored_name
            )));
        }
    }

    // RFC 6672, Section 2.4: one DNAME per name, and none beside a
    // delegation, which at any name but the apex is what NS records are.
    let has_at_name = |wanted: RecordType| records_at_name.iter().any(|r| r.record_type == wanted);
    if *record_type == RecordType::Dname {
        if has_at_name(RecordType::Dname) {
            return Err(ServiceError::record_conflict(format!(
                "a DNAME record already exists at '{}'; only one DNAME is allowed per name",
                stored_name
            )));
        }
        if !stored_name.is_apex() && has_at_name(RecordType::Ns) {
            return Err(ServiceError::record_conflict(format!(
                "a DNAME record cannot share the delegation '{}' with NS records",
                stored_name
            )));
        }
    }
    if *record_type == RecordType::Ns && !stored_name.is_apex() && has_at_name(RecordType::Dname) {
        return Err(ServiceError::record_conflict(format!(
            "NS records cannot delegate '{}' beside its DNAME record",
            stored_name
        )));
    }

    // A DS names a child zone's key (RFC 4034, Section 5); the zone's own
    // DS lives in its parent; the final-state check verifies its NS delegation.
    if *record_type == RecordType::Ds && stored_name.is_apex() {
        return Err(ServiceError::invalid_record_name(
            "DS records secure a child delegation; the zone's own DS belongs in the parent zone"
                .to_string(),
        ));
    }

    // RFC 2181, Section 5.2: one TTL per record set.
    if let Some(conflicting) = records_at_name
        .iter()
        .find(|r| r.record_type == *record_type && r.ttl != ttl)
    {
        return Err(ServiceError::record_conflict(format!(
            "TTL {} does not match the existing {} records for '{}' (TTL {}); records sharing a name and type share one TTL",
            ttl, record_type, stored_name, conflicting.ttl
        )));
    }

    Ok(())
}

/// Refuse a stored name that no longer fits the wire under `zone_name`, the
/// zone a rename or a rollback pairs it with.
pub(crate) fn validate_record_name_in_zone(
    name: &OwnerName,
    zone_name: &ZoneName,
) -> Result<(), ServiceError> {
    name.to_wire(zone_name).map(|_| ()).map_err(|e| {
        ServiceError::invalid_record_name(format!(
            "record name '{}' under zone '{}' {}",
            name, zone_name, e
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
    owner_name: &OwnerName,
    record_type: &RecordType,
    value: &str,
    ttl: Ttl,
    priority: Option<i32>,
) -> Result<AddResult, ServiceError> {
    // Only records sharing the owner name can conflict, so load just those
    // instead of the whole zone.
    let records_at_name =
        bindizr_db::record::list_by_name_tx(tx, zone.id, owner_name, LockLevel::Exclusive)
            .await
            .map_err(|e| {
                log::error!("Failed to load records: {}", e);
                ServiceError::internal_with_source("failed to load records", e)
            })?;

    if has_matching_rdata(records_at_name.iter(), record_type, value, priority) {
        return Ok(AddResult::Duplicate);
    }

    validate_record_constraints(
        &records_at_name,
        owner_name,
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
