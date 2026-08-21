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
    log_error,
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    repository::{RepositoryService, RepositoryTx},
};

/// Core value validation with the error mapped to `INVALID_RECORD_VALUE`.
fn validate_record_value(
    record_type: &RecordType,
    value: &str,
    priority: Option<i32>,
) -> Result<(), ServiceError> {
    record_type
        .validate_value(value, priority)
        .map_err(ServiceError::invalid_record_value)
}

pub(crate) fn parse_record_type(value: &str) -> Result<RecordType, ServiceError> {
    value
        .parse::<RecordType>()
        .map_err(|_| ServiceError::invalid_input(format!("invalid record type: {}", value)))
}

pub(crate) fn normalize_record_owner_name(
    input_name: &str,
    zone: &ZoneName,
) -> Result<OwnerName, ServiceError> {
    let owner = OwnerName::parse_in_zone(input_name, zone).map_err(|e| match e {
        ParseNameError::OutsideZone => ServiceError::invalid_record_name(format!(
            "record name '{}' is outside zone '{}'",
            input_name, zone
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
    records.into_iter().any(|r| {
        r.record_type == *record_type
            && record_type.values_equal(&r.value, r.priority, value, priority)
    })
}

/// Validate an add whose owner name has already been normalized to `stored_name`.
pub(crate) fn validate_record_add_constraints_normalized(
    zone_records: &[Record],
    stored_name: &OwnerName,
    record_type: &RecordType,
    value: &str,
    ttl: i32,
    priority: Option<i32>,
    except_record_id: Option<i32>,
) -> Result<(), ServiceError> {
    if *record_type == RecordType::SOA {
        return Err(ServiceError::invalid_input(
            "Cannot create SOA record manually".to_string(),
        ));
    }

    validate_record_value(record_type, value, priority)?;

    if *record_type == RecordType::CNAME && stored_name.is_apex() {
        return Err(ServiceError::invalid_record_name(
            "CNAME record cannot have '@' as name".to_string(),
        ));
    }

    let existing_records_with_name: Vec<_> = zone_records
        .iter()
        .filter(|r| r.name == *stored_name && except_record_id.map(|id| id != r.id).unwrap_or(true))
        .collect();

    if has_matching_rdata(
        existing_records_with_name.iter().copied(),
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
        let adding_null_mx = MxRecordValue::is_null_value(value, priority);
        let has_existing_null_mx = existing_records_with_name.iter().any(|r| {
            r.record_type == RecordType::MX && MxRecordValue::is_null_value(&r.value, r.priority)
        });
        let has_existing_mx = existing_records_with_name
            .iter()
            .any(|r| r.record_type == RecordType::MX);

        if (adding_null_mx && has_existing_mx) || (!adding_null_mx && has_existing_null_mx) {
            return Err(ServiceError::record_conflict(format!(
                "Null MX record for '{}' cannot coexist with other MX records",
                stored_name
            )));
        }
    }

    if !existing_records_with_name.is_empty() {
        if *record_type == RecordType::CNAME {
            return Err(ServiceError::record_conflict(format!(
                "Another record with name '{}' already exists in this zone, so CNAME cannot be used",
                stored_name
            )));
        }
        if existing_records_with_name
            .iter()
            .any(|r| r.record_type == RecordType::CNAME)
        {
            return Err(ServiceError::record_conflict(format!(
                "A CNAME record with name '{}' already exists in this zone",
                stored_name
            )));
        }
    }

    if *record_type == RecordType::NS && !stored_name.is_apex() {
        return Err(ServiceError::invalid_record_name(
            "NS records must use apex owner name '@'".to_string(),
        ));
    }

    // RFC 2181, Section 5.2: one TTL per RRset.
    if let Some(conflicting) = existing_records_with_name
        .iter()
        .find(|r| r.record_type == *record_type && r.ttl != ttl)
    {
        return Err(ServiceError::record_conflict(format!(
            "TTL {} does not match the existing {} RRset for '{}' (TTL {}); every record in an RRset must share one TTL",
            ttl, record_type, stored_name, conflicting.ttl
        )));
    }

    Ok(())
}

/// Reject deletions of the SOA record or the NS record referenced by `mname`.
pub(crate) fn validate_delete_constraints(
    zone: &Zone,
    deleting_records: &[Record],
) -> Result<(), ServiceError> {
    if deleting_records
        .iter()
        .any(|r| r.record_type == RecordType::SOA)
    {
        return Err(ServiceError::invalid_input(
            "Cannot delete SOA record".to_string(),
        ));
    }

    for record in deleting_records {
        if zone.is_mname(&record.record_type, &record.name, &record.value) {
            return Err(ServiceError::invalid_input(
                "Cannot delete NS record referenced by zone mname".to_string(),
            ));
        }
    }

    Ok(())
}

/// Validate an update whose new owner name is already normalized.
pub(super) fn validate_record_update_constraints_normalized(
    zone: &Zone,
    zone_records: &[Record],
    existing_record: &Record,
    updated_record: &Record,
) -> Result<(), ServiceError> {
    // SOA is managed via the zone's own fields and cannot be set on a record.
    if updated_record.record_type == RecordType::SOA {
        log_error!("Cannot update to SOA record type");
        return Err(ServiceError::invalid_input(
            "Cannot update to SOA record type".to_string(),
        ));
    }

    validate_record_add_constraints_normalized(
        zone_records,
        &updated_record.name,
        &updated_record.record_type,
        &updated_record.value,
        updated_record.ttl,
        updated_record.priority,
        Some(existing_record.id),
    )?;

    if zone.is_mname(
        &existing_record.record_type,
        &existing_record.name,
        &existing_record.value,
    ) {
        let still_primary = zone.is_mname(
            &updated_record.record_type,
            &updated_record.name,
            &updated_record.value,
        );

        if !still_primary {
            return Err(ServiceError::invalid_input(
                "Cannot modify the NS record referenced by zone mname".to_string(),
            ));
        }
    }

    Ok(())
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
        let zone_records = RepositoryService::list_records_by_zone_id_and_name_tx(
            tx,
            zone.id,
            owner_name,
            LockLevel::Exclusive,
        )
        .await
        .map_err(|e| {
            log_error!("Failed to load zone records: {}", e);
            ServiceError::internal("Failed to load zone records".to_string())
        })?;

        if has_matching_rdata(zone_records.iter(), record_type, value, priority) {
            return Ok(AddOutcome::Duplicate);
        }

        validate_record_add_constraints_normalized(
            &zone_records,
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
