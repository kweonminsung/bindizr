//! DNS record constraint validation: CNAME/NS/MX/SOA rules, duplicate
//! detection, and owner-name normalization.

use bindizr_core::dns::{
    name::{OwnerName, ParseNameError, ZoneName},
    record::MxRecordValue,
};
use bindizr_db::repository::LockLevel;

use super::RecordService;
use crate::{
    error::ServiceError,
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    repository::{RepositoryService, RepositoryTx},
};

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

/// Validate an add whose owner name has already been normalized to `stored_name`.
pub(crate) fn validate_record_add_constraints_normalized(
    records: &[Record],
    stored_name: &OwnerName,
    record_type: &RecordType,
    value: &str,
    ttl: i32,
    priority: Option<i32>,
    except_record_id: Option<i32>,
) -> Result<(), ServiceError> {
    record_type
        .validate_value(value, priority)
        .map_err(ServiceError::invalid_record_value)?;

    if *record_type == RecordType::CNAME && stored_name.is_apex() {
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
            "Record '{}' {} '{}' already exists in this zone",
            stored_name, record_type, value
        )));
    }

    if *record_type == RecordType::MX {
        let adding_null_mx = MxRecordValue::parse(value, priority).is_ok_and(|mx| mx.is_null());
        let has_existing_null_mx = records_at_name.iter().any(|r| {
            r.record_type == RecordType::MX
                && MxRecordValue::parse(&r.value, r.priority).is_ok_and(|mx| mx.is_null())
        });
        let has_existing_mx = records_at_name
            .iter()
            .any(|r| r.record_type == RecordType::MX);

        if (adding_null_mx && has_existing_mx) || (!adding_null_mx && has_existing_null_mx) {
            return Err(ServiceError::record_conflict(format!(
                "Null MX record for '{}' cannot coexist with other MX records",
                stored_name
            )));
        }
    }

    if !records_at_name.is_empty() {
        if *record_type == RecordType::CNAME {
            return Err(ServiceError::record_conflict(format!(
                "Another record with name '{}' already exists in this zone, so CNAME cannot be used",
                stored_name
            )));
        }
        if records_at_name
            .iter()
            .any(|r| r.record_type == RecordType::CNAME)
        {
            return Err(ServiceError::record_conflict(format!(
                "A CNAME record with name '{}' already exists in this zone",
                stored_name
            )));
        }
    }

    // A DS names a child zone's key (RFC 4034, Section 5); the zone's own
    // DS lives in its parent. The NS coupling is checked at versioning.
    if *record_type == RecordType::DS && stored_name.is_apex() {
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

/// Validate an update whose new owner name is already normalized.
pub(crate) fn validate_record_update_constraints_normalized(
    records: &[Record],
    existing_record: &Record,
    updated_record: &Record,
) -> Result<(), ServiceError> {
    validate_record_add_constraints_normalized(
        records,
        &updated_record.name,
        &updated_record.record_type,
        &updated_record.value,
        updated_record.ttl,
        updated_record.priority,
        Some(existing_record.id),
    )
}

/// What an add resolves to against the records already in the zone.
pub(crate) enum AddOutcome {
    /// Nothing holds this rdata and every constraint passed.
    New,
    Duplicate,
}

impl RecordService {
    /// Validate an add against conflicting records loaded within the caller's
    /// transaction, reporting an rdata-identical record as
    /// [`AddOutcome::Duplicate`] rather than rejecting it — RFC 2136,
    /// Section 3.4.2.2 makes it a silent no-op. The API paths call the
    /// validator directly, where the same case stays a conflict.
    pub(crate) async fn validate_add_tx(
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        owner_name: &OwnerName,
        record_type: &RecordType,
        value: &str,
        ttl: i32,
        priority: Option<i32>,
    ) -> Result<AddOutcome, ServiceError> {
        // Only records sharing the owner name can conflict, so load just those
        // instead of the whole zone.
        let records_at_name = RepositoryService::list_records_by_name_tx(
            tx,
            zone.id,
            owner_name,
            LockLevel::Exclusive,
        )
        .await
        .map_err(|e| {
            log::error!("Failed to load records: {}", e);
            ServiceError::internal("Failed to load records")
        })?;

        if has_matching_rdata(records_at_name.iter(), record_type, value, priority) {
            return Ok(AddOutcome::Duplicate);
        }

        validate_record_add_constraints_normalized(
            &records_at_name,
            owner_name,
            record_type,
            value,
            ttl,
            priority,
            None,
        )?;

        Ok(AddOutcome::New)
    }
}

#[cfg(test)]
mod tests;
